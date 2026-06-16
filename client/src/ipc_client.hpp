#pragma once

#include "avipc/message.hpp"

#include <array>
#include <atomic>
#include <boost/asio/io_context.hpp>
#include <boost/asio/local/stream_protocol.hpp>
#include <boost/asio/steady_timer.hpp>
#include <deque>
#include <functional>
#include <string>
#include <thread>

/// @file ipc_client.hpp
/// @brief Asynchronous client connection to the antivirus daemon.

namespace av::client {

/// @brief Connects to the daemon's Unix socket on a background ASIO thread.
///
/// Incoming messages are demultiplexed into events and replies and delivered
/// through callbacks invoked on the network thread; the GUI layer is expected to
/// marshal them onto its own event loop. Commands are sent with @ref send.
class IpcClient {
  public:
    /// @brief Callback invoked for each asynchronous event from the daemon.
    using EventCallback = std::function<void(const ipc::Event&)>;
    /// @brief Callback invoked for each reply to a command.
    using ReplyCallback = std::function<void(const ipc::Reply&)>;
    /// @brief Callback invoked when the connection state changes.
    using StateCallback = std::function<void(bool connected, const std::string& detail)>;

    /// @brief Construct the client and start the background thread.
    /// @param socket_path Daemon socket path to connect to.
    /// @param on_event Event callback.
    /// @param on_reply Reply callback.
    /// @param on_state Connection-state callback.
    IpcClient(std::string socket_path, EventCallback on_event, ReplyCallback on_reply,
              StateCallback on_state);

    /// @brief Stop the background thread and close the connection.
    ~IpcClient();

    IpcClient(const IpcClient&) = delete;
    IpcClient& operator=(const IpcClient&) = delete;

    /// @brief Queue a command for delivery to the daemon.
    /// @param command Command to send.
    void send(const ipc::Command& command);

    /// @brief Whether the client is currently connected.
    /// @return True if the socket is connected.
    bool connected() const noexcept { return connected_.load(); }

  private:
    void do_connect();
    void do_read();
    void do_write();
    void handle_payload(const std::string& payload);

    boost::asio::io_context io_;
    boost::asio::local::stream_protocol::socket socket_;
    boost::asio::steady_timer reconnect_timer_;
    std::string socket_path_;
    EventCallback on_event_;
    ReplyCallback on_reply_;
    StateCallback on_state_;

    std::string read_buffer_;
    std::array<char, 4096> chunk_{};
    std::deque<std::string> write_queue_;
    std::atomic<bool> connected_{false};
    std::thread worker_;
};

}
