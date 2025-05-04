#include <sys/types.h>
#include <sys/wait.h>

#include <iostream>
#include <algorithm>
#include <fstream>
#include <map>
#include <chrono>
#include <thread>

#include "webserver.hpp"
#include "env.hpp"
#include <sys/stat.h>

#include <libpq-fe.h>

static void processNotice(void *arg, const char *message) {
//    UNUSED(arg);
//    UNUSED(message);

    // do nothing
}

int main(int argc, char* argv[]) {
    serverenv env;

    PGresult* res = NULL;

    env.conn = PQconnectdb("user=ackoncoord password=ackoncoord host=localhost dbname=ackoncoord");
    if(PQstatus(env.conn) != CONNECTION_OK) {
	std::cout << "Can't connect to db" << std::endl;
    }
    PQsetNoticeProcessor(env.conn, processNotice, NULL);

    startWebServer(&env);
    return 0;
}
