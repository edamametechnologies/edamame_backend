fn main() {
    // Dotenv build with a specific env path
    let config = dotenv_build::Config {
        filename: std::path::Path::new("../secrets/lambda-signature.env"),
        recursive_search: false,
        fail_if_missing_dotenv: false,
    };
    dotenv_build::output(config).unwrap();
}
