#include <boost/program_options.hpp>
#include <charter/abci/server.hpp>
#include <string>

int main(int argc, char* argv[]) {
  auto grpc_port = std::string{};

  auto vm = boost::program_options::variables_map{};
  auto description = boost::program_options::options_description{"Charter"};
  description.add_options()("help,h", "Show the help message")(
      "grpc-port,g",
      boost::program_options::value<std::string>(&grpc_port)->default_value(
          "0.0.0.0:50051"),
      "IP:Port for the ABCI server")("verbose,v", "Enable verbose output");
  boost::program_options::store(
      boost::program_options::parse_command_line(argc, argv, description), vm);
  boost::program_options::notify(vm);

  if (vm.contains("help")) {
    std::cout << description << std::endl;
    return 0;
  }

  if (vm.contains("verbose")) {

  }
}