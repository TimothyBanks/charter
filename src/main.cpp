#include <csignal>
#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>
#include <health/health.grpc.pb.h>
#include <spdlog/async.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <boost/program_options.hpp>
#include <charter/abci/server.hpp>
#include <string>

std::atomic<bool>& shutdown_requested() {
    static std::atomic<bool> requested{};
    return requested;
}

void signal_handler(int) {
    shutdown_requested() = true;
}

int main(int argc, char* argv[]) {
  std::signal(SIGINT, signal_handler);

  spdlog::init_thread_pool(8192, 1);
  spdlog::set_pattern("%H:%M:%S.%e [%^%l%$] [%n] %v");
  spdlog::set_level(spdlog::level::debug);

  auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
  auto file_sink =
      std::make_shared<spdlog::sinks::basic_file_sink_mt>("app.log", false);

  auto logger = std::make_shared<spdlog::async_logger>(
      "main", spdlog::sinks_init_list{console_sink, file_sink},
      spdlog::thread_pool(),
      spdlog::async_overflow_policy::block  // or overrun_oldest
  );

  spdlog::set_default_logger(logger);
  // This one has source line and function
  //   spdlog::set_pattern("%H:%M:%S.%e [%^%l%$] [%n] %s:%# %! - %v");

  auto grpc_port = std::string{};
  auto verbose = false;

  auto vm = boost::program_options::variables_map{};
  auto description = boost::program_options::options_description{"Charter"};
  description.add_options()("help,h", "Show the help message")(
      "grpc-port,g",
      boost::program_options::value<std::string>(&grpc_port)
          ->default_value("0.0.0.0:26658"),
      "IP:Port for the ABCI server")("verbose,v", "Enable verbose output");
  boost::program_options::store(
      boost::program_options::parse_command_line(argc, argv, description), vm);
  boost::program_options::notify(vm);

  if (vm.contains("help")) {
    std::cout << description << std::endl;
    return 0;
  }

  if (vm.contains("verbose")) {
    verbose = true;
  }

  auto copy = grpc_port;
  std::ranges::replace(copy, ':', ' ');
  spdlog::info("gRPC service listening on {}", copy);

  grpc::EnableDefaultHealthCheckService(true);
  grpc::reflection::InitProtoReflectionServerBuilderPlugin();

  auto grpc_listener = charter::abci::listener();
  auto grpc_builder = grpc::ServerBuilder();
  grpc_builder.AddListeningPort(grpc_port, grpc::InsecureServerCredentials());
  grpc_builder.RegisterService(&grpc_listener);
  auto grpc_server = std::unique_ptr<grpc::Server>(grpc_builder.BuildAndStart());
  grpc_server->GetHealthCheckService()->SetServingStatus(false);

  auto threads = std::vector<std::thread>{};
  threads.emplace_back([&] { grpc_server->Wait(); });
  threads.emplace_back([&] {
    while (!shutdown_requested()) {
        grpc_server->GetHealthCheckService()->SetServingStatus(true);
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    grpc_server->GetHealthCheckService()->SetServingStatus(false);
    grpc_server->Shutdown();
  });

  for (auto& t : threads) {
    t.join();
  }

  spdlog::shutdown();
  return 0;
}