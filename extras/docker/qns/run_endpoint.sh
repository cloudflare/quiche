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
QUICHE_CLIENT=quiche-client
QUICHE_SERVER=quiche-server
QUICHE_CLIENT_OPT="--no-verify --dump-responses ${DOWNLOAD_DIR}"
QUICHE_SERVER_OPT="--no-retry --cert examples/cert.crt --key examples/cert.key"
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
        ;;
    *)
        echo "unsupported"
        exit 127
        ;;
    esac
}

run_quiche_client_tests () {
    # TODO: https://github.com/marten-seemann/quic-interop-runner/issues/61
    # remove this sleep when the issue above is resolved.
    sleep 3
    $QUICHE_DIR/$QUICHE_CLIENT $QUICHE_CLIENT_OPT \
        $CLIENT_PARAMS $REQUESTS >& $LOG

}

run_quiche_server_tests() {
    $QUICHE_DIR/$QUICHE_SERVER --listen 0.0.0.0:443 --root $WWW_DIR \
        $SERVER_PARAMS $QUICHE_SERVER_OPT >& $LOG
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
    # Wait for the simulator to start up.
    /wait-for-it.sh sim:57832 -s -t 30
    echo "## Starting quiche server..."
    echo "## Server params: $SERVER_PARAMS"
    echo "## Test case: $TESTCASE"
    run_quiche_server_tests
fi
