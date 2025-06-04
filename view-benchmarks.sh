#!/bin/bash
# Local JMH Visualizer Helper
# This script opens JMH Visualizer with your benchmark results in one click

# Function to display help message
show_help() {
    echo "Usage: ./view-benchmarks.sh [benchmark-file.json]"
    echo ""
    echo "This script opens the JMH Visualizer website with your benchmark results."
    echo ""
    echo "If no file is specified, the script will search for benchmark files in common locations:"
    echo "  - jmh-result.json"
    echo "  - jmh-results.json"
    echo "  - target/jmh-result.json"
    echo "  - benchmark-results/jmh-result.json"
    echo "  - Or any file matching jmh-result*.json"
    echo ""
    echo "Examples:"
    echo "  ./view-benchmarks.sh                        # Auto-detect benchmark file"
    echo "  ./view-benchmarks.sh path/to/results.json   # Use specific file"
    exit 0
}

# Process command line arguments
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    show_help
elif [ $# -gt 0 ]; then
    if [ -f "$1" ]; then
        RESULT_FILE="$1"
    else
        echo "Error: File '$1' not found."
        echo "Run './view-benchmarks.sh --help' for usage information."
        exit 1
    fi
else
    # Default benchmark result file
    RESULT_FILE="jmh-result.json"
fi

# Check for the benchmark file
if [ ! -f "$RESULT_FILE" ]; then
    # Try to find the file
    if [ -f "target/$RESULT_FILE" ]; then
        RESULT_FILE="target/$RESULT_FILE"
    elif [ -f "benchmark-results/$RESULT_FILE" ]; then
        RESULT_FILE="benchmark-results/$RESULT_FILE"
    elif [ -f "jmh-results.json" ]; then
        # Check for the alternative filename
        RESULT_FILE="jmh-results.json"
    elif [ -f "target/jmh-results.json" ]; then
        RESULT_FILE="target/jmh-results.json"
    elif [ -f "benchmark-results/jmh-results.json" ]; then
        RESULT_FILE="benchmark-results/jmh-results.json"
    else
        # Try to find any JMH result file
        FOUND_FILE=$(find . -name "jmh-result*.json" -type f | head -1)
        if [ -n "$FOUND_FILE" ]; then
            RESULT_FILE="$FOUND_FILE"
        else
            echo "Error: Could not find benchmark result file."
            echo "Please run benchmarks first or specify the path to your result file."
            exit 1
        fi
    fi
fi

# Get the absolute path of the result file
RESULT_PATH=$(readlink -f "$RESULT_FILE")

echo "Found benchmark results file: $RESULT_PATH"
echo "Opening JMH Visualizer..."

# Determine the browser to use on Ubuntu and other systems
BROWSER=""

# Generic Linux/Unix browser opener - try this first as it handles system preferences
if command -v xdg-open &> /dev/null; then
    BROWSER="xdg-open"
# macOS browser opener
elif command -v open &> /dev/null; then
    BROWSER="open"
# Windows browser opener
elif command -v explorer &> /dev/null; then
    BROWSER="explorer"
# Ubuntu-specific fallbacks if xdg-open isn't working
elif command -v firefox &> /dev/null; then
    BROWSER="firefox"
elif command -v chromium-browser &> /dev/null; then
    BROWSER="chromium-browser"
elif command -v google-chrome &> /dev/null; then
    BROWSER="google-chrome"
elif command -v sensible-browser &> /dev/null; then
    BROWSER="sensible-browser"
fi

if [ -n "$BROWSER" ]; then
    echo "Using browser: $BROWSER"
    
    # Open JMH Visualizer with the local file directly
    URL="https://jmh.morethan.io/?source=file://$RESULT_PATH"
    
    # Handle browser launching to suppress GTK warnings
    case "$BROWSER" in
        firefox|chromium-browser|google-chrome)
            # For browsers that might show GTK warnings, redirect stderr
            $BROWSER "$URL" 2>/dev/null & 
            ;;
        xdg-open)
            # On Ubuntu, redirect all output to suppress GTK warnings
            $BROWSER "$URL" >/dev/null 2>&1 &
            ;;
        *)
            # For other browsers, standard redirection
            $BROWSER "$URL" &>/dev/null &
            ;;
    esac
else
    echo "Could not find a command to open a browser."
    echo "Please open https://jmh.morethan.io/ manually and upload the file:"
    echo "$RESULT_PATH"
    exit 1
fi

echo "JMH Visualizer has been opened in your browser."
echo "The benchmark file has been automatically loaded: $RESULT_PATH"
echo "If the file didn't load automatically, you can manually upload it using the JMH Visualizer interface."
