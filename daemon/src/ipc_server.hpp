#pragma once

#include "avipc/message.hpp"

#include <boost/asio/io_context.hpp>
#include <boost/asio/local/stream_protocol.hpp>
#include <functional>
#include <memory>
#include <string>
#include <vector>

/// @file ipc_server.hpp
/// @brief Unix-domain-socket server delivering events to and accepting commands
///        from GUI clients.

namespace av::daemon {

class IpcSession;

/// @brief Accepts client connections and fans events out to all of them.
///
/// Clients send @ref av::ipc::Command messages and receive @ref av::ipc::Reply
/// responses; the daemon pushes asynchronous @ref av::ipc::Event notifications
/// to every connected client via @ref broadcast.
class IpcServer {
  public:
    /// @brief Handler turning a client command into a reply.
    using CommandHandler = std::function<ipc::Reply(const ipc::Command&)>;

    /// @brief Create the server and start listening.
    /// @param io ASIO execution context driving the server.
    /// @param socket_path Filesystem path for the listening Unix socket.
    /// @param handler Callback invoked for each received command.
    /// @throws av::IoError if the socket cannot be created or bound.
    IpcServer(boost::asio::io_context& io, const std::string& socket_path, CommandHandler handler);

    /// @brief Remove the socket file on shutdown.
    ~IpcServer();

    IpcServer(const IpcServer&) = delete;
    IpcServer& operator=(const IpcServer&) = delete;

    /// @brief Push an event to every connected client.
    /// @param event Event to deliver.
    void broadcast(const ipc::Event& event);

    /// @brief Dispatch a command to the registered handler.
    /// @param command Command received from a client.
    /// @return The handler's reply (or an error reply if the handler throws).
    ipc::Reply dispatch(const ipc::Command& command);

  private:
    void do_accept();

    boost::asio::io_context& io_;
    boost::asio::local::stream_protocol::acceptor acceptor_;
    std::string socket_path_;
    CommandHandler handler_;
    std::vector<std::weak_ptr<IpcSession>> sessions_;
};

}
