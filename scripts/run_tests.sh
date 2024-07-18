
test_name=""
no_log=false

# Function to display usage information
usage() {
    echo "Usage: $0 [-h] [-t test_name] [--no-log]"
    echo "Options:"
    echo "  -h               Display this help message"
    echo "  -t <test_name>   Test name"
    echo "  --no-log         Disable unit test log"
    exit 1
}

# Parse command-line options
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -h) usage ;;
        -t) test_name="$2"; shift ;;
        --no-log) no_log=true ;;
        -*) echo "Invalid option: $1" >&2; usage ;;
        *) echo "Unknown parameter: $1" >&2; usage ;;
    esac
    shift
done
export RUSTFLAGS="-C link-arg=-lasan"
# Set the command to run the tests
test_command="cargo test"
if [ -n "$test_name" ]; then
    test_command+=" $test_name"
fi

# Add nocapture flag if no_log is false
if [ "$no_log" = false ]; then
    test_command+=" -- --nocapture"
fi

# Run the test command
echo "Running command: $test_command"
eval $test_command
