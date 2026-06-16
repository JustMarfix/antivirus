#include "ipc_server.hpp"

#include "avcore/error.hpp"
#include "avipc/codec.hpp"

#include <array>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <cstdio>
#include <deque>
#include <filesystem>
#include <system_error>

namespace av::daemon {

namespace asio = boost::asio;
using local_socket = asio::local::stream_protocol::socket;

/// @brief One connected client connection. Reads framed commands and writes
///        framed replies/events. Lifetime is managed via shared_from_this so
///        in-flight asynchronous operations keep the session alive.
class IpcSession : public std::enable_shared_from_this<IpcSession> {
  public:
    IpcSession(local_socket socket, IpcServer& server)
        : socket_(std::move(socket)), server_(server) {}

    void start() { do_read(); }

    void deliver(const std::string& framed) {
        bool idle = write_queue_.empty();
        write_queue_.push_back(framed);
        if (idle) {
            do_write();
        }
    }

  private:
    void do_read() {
        auto self = shared_from_this();
        socket_.async_read_some(asio::buffer(chunk_),
                                [this, self](const boost::system::error_code& ec, std::size_t n) {
                                    if (ec) {
                                        return;
                                    }
                                    read_buffer_.append(chunk_.data(), n);
                                    try {
                                        while (auto payload = ipc::try_unframe(read_buffer_)) {
                                            ipc::Command command = ipc::decode_command(*payload);
                                            ipc::Reply reply = server_.dispatch(command);
                                            deliver(ipc::frame(ipc::encode_reply(reply)));
                                        }
                                    } catch (const AvException&) {
                                        return;
                                    }
                                    do_read();
                                });
    }

    void do_write() {
        auto self = shared_from_this();
        asio::async_write(socket_, asio::buffer(write_queue_.front()),
                          [this, self](const boost::system::error_code& ec, std::size_t) {
                              if (ec) {
                                  return;
                              }
                              write_queue_.pop_front();
                              if (!write_queue_.empty()) {
                                  do_write();
                              }
                          });
    }

    local_socket socket_;
    IpcServer& server_;
    std::string read_buffer_;
    std::array<char, 4096> chunk_{};
    std::deque<std::string> write_queue_;
};

IpcServer::IpcServer(asio::io_context& io, const std::string& socket_path, CommandHandler handler)
    : io_(io), acceptor_(io), socket_path_(socket_path), handler_(std::move(handler)) {
    std::error_code remove_ec;
    std::filesystem::remove(socket_path_, remove_ec);
    try {
        asio::local::stream_protocol::endpoint endpoint(socket_path_);
        acceptor_.open(endpoint.protocol());
        acceptor_.bind(endpoint);
        acceptor_.listen();
    } catch (const boost::system::system_error& e) {
        throw IoError(std::string("IPC server bind failed on '") + socket_path_ + "': " + e.what());
    }
    do_accept();
}

IpcServer::~IpcServer() {
    std::error_code ec;
    std::filesystem::remove(socket_path_, ec);
}

void IpcServer::do_accept() {
    acceptor_.async_accept([this](const boost::system::error_code& ec, local_socket socket) {
        if (!ec) {
            auto session = std::make_shared<IpcSession>(std::move(socket), *this);
            sessions_.push_back(session);
            session->start();
        }
        do_accept();
    });
}

ipc::Reply IpcServer::dispatch(const ipc::Command& command) {
    try {
        return handler_(command);
    } catch (const AvException& e) {
        return ipc::Reply{false, e.what(), "error", "", {}};
    }
}

void IpcServer::broadcast(const ipc::Event& event) {
    std::string framed = ipc::frame(ipc::encode_event(event));
    std::vector<std::weak_ptr<IpcSession>> live;
    live.reserve(sessions_.size());
    for (const auto& weak : sessions_) {
        if (auto session = weak.lock()) {
            session->deliver(framed);
            live.push_back(weak);
        }
    }
    sessions_.swap(live);
}

}
