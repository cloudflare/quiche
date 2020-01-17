#!/bin/bash
set -e

# Set up the routing needed for the simulation
/setup.sh

# The following variables are available for use:
# - ROLE contains the role of this execution context, client or server
# - SERVER_PARAMS contains user-supplied command line parameters
# - CLIENT_PARAMS contains user-supplied command line parameters

QUICHE_DIR=/quiche
WWW_DIR=/www
DOWNLOAD_DIR=/downloads
QUICHE_CLIENT=client
QUICHE_SERVER=server
QUICHE_CLIENT_OPT="--no-verify"
QUICHE_SERVER_OPT="--no-retry"
LOG_DIR=/logs
LOG=$LOG_DIR/log.txt

check_testcase () {
    TESTNAME=$1

    case $1 in
    handshake | resumption | multiconnect )
        echo "supported"
        ;;
    transfer )
        echo "supported"
        RUST_LOG="info"
        ;;
    retry )
        echo "supported"
        QUICHE_SERVER_OPT=""
        ;;
    http3 )
        echo "supported"
        QUICHE_CLIENT=http3-client
        QUICHE_SERVER=http3-server
        ;;
    *)
        echo "unsupported"
        exit 127
        ;;
    esac
}

run_quiche_client_tests () {
    for req in $REQUESTS
    do
        # get path only from the url
        file=$(echo $req | perl -F'/' -an -e 'print $F[-1]')
        $QUICHE_DIR/$QUICHE_CLIENT $QUICHE_CLIENT_OPT \
            $CLIENT_PARAMS $req > $DOWNLOAD_DIR/$file 2> $LOG || exit 127
    done
}

run_quiche_server_tests() {
    $QUICHE_DIR/$QUICHE_SERVER --listen 0.0.0.0:443 --root $WWW_DIR \
        $SERVER_PARAMS $QUICHE_SERVER_OPT 2> $LOG || exit 127
}

# Update config based on test case
check_testcase $TESTCASE

# Create quiche log directory
mkdir -p $LOG_DIR

if [ "$ROLE" == "client" ]; then
    # Wait for the simulator to start up.
    /wait-for-it.sh sim:57832 -s -t 30
    echo "## Starting quiche client..."
    echo "## Client params: $CLIENT_PARAMS"
    echo "## Requests: $REQUESTS"
    echo "## Test case: $TESTCASE"
    run_quiche_client_tests
elif [ "$ROLE" == "server" ]; then
    echo "## Starting quiche server..."
    echo "## Server params: $SERVER_PARAMS"
    echo "## Test case: $TESTCASE"
    run_quiche_server_tests
fi
