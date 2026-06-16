#include "ipc_client.hpp"

#include "avcore/error.hpp"
#include "avipc/codec.hpp"

#include <boost/asio/connect.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/write.hpp>
#include <chrono>

namespace av::client {

namespace asio = boost::asio;

IpcClient::IpcClient(std::string socket_path, EventCallback on_event, ReplyCallback on_reply,
                     StateCallback on_state)
    : socket_(io_), reconnect_timer_(io_), socket_path_(std::move(socket_path)),
      on_event_(std::move(on_event)), on_reply_(std::move(on_reply)),
      on_state_(std::move(on_state)) {
    asio::post(io_, [this] { do_connect(); });
    worker_ = std::thread([this] { io_.run(); });
}

IpcClient::~IpcClient() {
    io_.stop();
    if (worker_.joinable()) {
        worker_.join();
    }
}

void IpcClient::do_connect() {
    asio::local::stream_protocol::endpoint endpoint(socket_path_);
    socket_.async_connect(endpoint, [this](const boost::system::error_code& ec) {
        if (ec) {
            connected_.store(false);
            if (on_state_) {
                on_state_(false, "connect failed: " + ec.message());
            }
            reconnect_timer_.expires_after(std::chrono::seconds(1));
            reconnect_timer_.async_wait([this](const boost::system::error_code& wait_ec) {
                if (!wait_ec) {
                    do_connect();
                }
            });
            return;
        }
        connected_.store(true);
        if (on_state_) {
            on_state_(true, "connected");
        }
        if (!write_queue_.empty()) {
            do_write();
        }
        do_read();
    });
}

void IpcClient::handle_payload(const std::string& payload) {
    switch (ipc::peek_type(payload)) {
    case ipc::MessageType::Event:
        if (on_event_) {
            on_event_(ipc::decode_event(payload));
        }
        break;
    case ipc::MessageType::Reply:
        if (on_reply_) {
            on_reply_(ipc::decode_reply(payload));
        }
        break;
    case ipc::MessageType::Command:
        break;
    }
}

void IpcClient::do_read() {
    socket_.async_read_some(
        asio::buffer(chunk_), [this](const boost::system::error_code& ec, std::size_t n) {
            if (ec) {
                connected_.store(false);
                socket_ = asio::local::stream_protocol::socket(io_);
                if (on_state_) {
                    on_state_(false, "disconnected");
                }
                reconnect_timer_.expires_after(std::chrono::seconds(1));
                reconnect_timer_.async_wait([this](const boost::system::error_code& wait_ec) {
                    if (!wait_ec) {
                        do_connect();
                    }
                });
                return;
            }
            read_buffer_.append(chunk_.data(), n);
            try {
                while (auto payload = ipc::try_unframe(read_buffer_)) {
                    handle_payload(*payload);
                }
            } catch (const AvException&) {
                read_buffer_.clear();
            }
            do_read();
        });
}

void IpcClient::do_write() {
    asio::async_write(socket_, asio::buffer(write_queue_.front()),
                      [this](const boost::system::error_code& ec, std::size_t) {
                          if (ec) {
                              return;
                          }
                          write_queue_.pop_front();
                          if (!write_queue_.empty()) {
                              do_write();
                          }
                      });
}

void IpcClient::send(const ipc::Command& command) {
    std::string framed = ipc::frame(ipc::encode_command(command));
    asio::post(io_, [this, framed] {
        bool idle = write_queue_.empty();
        write_queue_.push_back(framed);
        if (connected_.load() && idle) {
            do_write();
        }
    });
}

}
