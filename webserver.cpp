#include <regex>
#include <memory>
#include <map>
#include <cstdint>
#include <iostream>
#include <fstream>
#include <cstring>
#include <evhttp.h>
#include <sstream>
#include <algorithm>

#include <filesystem>
namespace fs = std::filesystem;

#include "json.hpp"
#include "webserver.hpp"
#include "sign.hpp"
#include "format.hpp"
#include "slots.hpp"

#define SERVER_NAME "ackon-server/1.0"
//#define SERVER_POWERED "HA Solutions"

using json = nlohmann::json;

std::string urlDecode(std::string &SRC) {
    std::string ret;
    char ch;
    int i, ii;
    for (i=0; i<SRC.length(); i++) {
        if (SRC[i]=='%') {
            std::sscanf(SRC.substr(i+1,2).c_str(), "%x", &ii);
            ch=static_cast<char>(ii);
            ret+=ch;
            i=i+2;
        } else {
            ret+=SRC[i];
        }
    }
    return (ret);
}

long long getCoordinatorId() {
    std::ifstream t("var/coordinator-login");
    std::string userconfig((std::istreambuf_iterator<char>(t)),
                 std::istreambuf_iterator<char>());
    json config = json::parse(userconfig);
    std::string idstr = config["coordinator"];
    return std::stoll(idstr);
}

std::map<std::string, std::string> parseParams(std::string in) {
    std::map<std::string, std::string> params;
    std::stringstream s_params(in);
    std::string pair;

    while(std::getline(s_params, pair, '&'))
    {
	std::stringstream s_pair(pair);
	std::string name, val;
	std::getline(s_pair, name, '=');
	std::getline(s_pair, val, '=');
	params.insert(std::pair<std::string, std::string>(name, urlDecode(val)));
    }
    return params;
}

void gen_random(char *s, int l) {
    for (int c; c=rand()%62, *s++ = (c+"07="[(c+16)/26])*(l-->0););
}

int startWebServer(serverenv *env) {
  if (!event_init()) {
    std::cerr << "Failed to init libevent." << std::endl;
    return -1;
  }

  char const SrvAddress[] = "0.0.0.0";
  std::uint16_t SrvPort = 8086;

  std::cout << "webserver run with urls:" << std::endl;

  std::unique_ptr<evhttp, decltype(&evhttp_free)> Server(evhttp_start(SrvAddress, SrvPort), &evhttp_free);
  if (!Server) {
    std::cerr << "Failed to init http server." << std::endl;
    return -1;
  }
  void (*OnReq)(evhttp_request *req, void *) = [] (evhttp_request *req, void *passed) {
    serverenv *env = (serverenv*)passed;
    auto *OutBuf = evhttp_request_get_output_buffer(req);
    if (!OutBuf) {
       return;
    }
    const char *query = evhttp_request_get_uri(req);
    evhttp_add_header(req->output_headers, "Server", SERVER_NAME);
//    evhttp_add_header(req->output_headers, "X-Powered-By", SERVER_POWERED);

    if (!query) {
        evhttp_send_reply(req, 404, "", OutBuf);
	return;
    }

    std::size_t pos = std::string(query).find("?");
    std::string uri = std::string(query).substr(0, pos);

    if (std::string(uri).compare("/login/signin") == 0) {
	//GET parametes: login, password

        std::string params = std::string(query).substr(pos+1);
        std::map<std::string, std::string> paramsMap = parseParams(params);

	if ((paramsMap.find("login") == paramsMap.end()) ||
	    (paramsMap.find("password") == paramsMap.end())) {
	    std::string html = "Bad request (required params: login, password)";
            evbuffer_add_printf(OutBuf, "%s", html.c_str());
            evhttp_send_reply(req, 400, "", OutBuf);
	    return;
	}

//        std::string html = "Hello on /login/signin!\n\nlogin=";
//	html.append(paramsMap["login"]);
//	html.append("\n\npassword=");
//	html.append(paramsMap["password"] + "\n\n");
	
	PGresult* res = NULL;
	const char* query = "SELECT * FROM users WHERE login=$1 AND password_hash=$2;";
	const char* qparams[2];
	qparams[0] = paramsMap["login"].c_str();
	qparams[1] = paramsMap["password"].c_str();
	res = PQexecParams(env->conn, query, 2, NULL, qparams, NULL, NULL, 0);
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
	    std::cout << "Can't select from db" << std::endl;
	}
	int ncols = PQnfields(res);
	int nrows = PQntuples(res);
	bool found=false;
	unsigned long long userid = 0;
	for(int i = 0; i < nrows; i++) {
	    char* id = PQgetvalue(res, i, 0);
	    char* login = PQgetvalue(res, i, 1);
	    char* password = PQgetvalue(res, i, 2);
	    found=true;
	    userid = atoll(id);
//	    html.append("Id: " + std::string(id) + "\n");
	}
	std::string html = "";
	if ((found) && (userid > 0)) {
	    //
	    const char* insert = "INSERT INTO nodes (user_id, token) VALUES ($1, $2)  RETURNING ID;";
	    char* iparams[2];
	    iparams[0] = (char*)std::to_string(userid).c_str();
	    iparams[1] = (char*)malloc(250);
	    bzero(iparams[1], 250);
	    gen_random(iparams[1], 60);
	    res = PQexecParams(env->conn, insert, 2, NULL, iparams, NULL, NULL, 0);
//	    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
	    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		html.append("{ \"status\":\"fail\" }");
	        evhttp_add_header(req->output_headers, "Content-Type", "application/json");
	        evbuffer_add_printf(OutBuf, "%s", html.c_str());
	        evhttp_send_reply(req, HTTP_OK, "", OutBuf);
	    } else {
		char* nodeid = PQgetvalue(res, 0, 0);
		html.append("{ \"status\":\"ok\", \"token\":\"" +std::string(iparams[1])+ "\", \"runnerid\":\"" + std::string(nodeid) + "\" }");
	        evhttp_add_header(req->output_headers, "Content-Type", "application/json");
	        evbuffer_add_printf(OutBuf, "%s", html.c_str());
	        evhttp_send_reply(req, HTTP_OK, "", OutBuf);
	    }
	} else {
	    html.append("{ \"status\":\"not login\" }");
	    evhttp_add_header(req->output_headers, "Content-Type", "application/json");
	    evbuffer_add_printf(OutBuf, "%s", html.c_str());
	    evhttp_send_reply(req, HTTP_OK, "", OutBuf);
	}
    } else if (std::string(uri).compare("/login/pubkey") == 0) {
	//POST json:
	/*
        {
            "sendpubkey": {
                "userid": userid,
                "token": token,
                "pubkey": pubkey,
            }
        }
	*/
	struct evbuffer* buf = evhttp_request_get_input_buffer(req);
	size_t len = evbuffer_get_length(buf);
	char* data = (char*)malloc(len + 1);
	bzero(data, len+1);
	evbuffer_copyout(buf, data, len);
	json responseJson = json::parse(std::string(data));
	json object = responseJson["sendpubkey"];
	std::string userid = object["runnerid"];
	std::string token = object["token"];
	std::string pubkey = object["pubkey"];

	PGresult* res = NULL;
	const char* query = "SELECT * FROM nodes WHERE id=$1 AND token=$2;";
	const char* qparams[2];
	qparams[0] = userid.c_str();
	qparams[1] = token.c_str();
	res = PQexecParams(env->conn, query, 2, NULL, qparams, NULL, NULL, 0);
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
	    std::cout << "Can't select from db" << std::endl;
	    std::string html = ("{ \"status\":\"fail\" }");
	    evhttp_add_header(req->output_headers, "Content-Type", "application/json");
	    evbuffer_add_printf(OutBuf, "%s", html.c_str());
	    evhttp_send_reply(req, HTTP_OK, "", OutBuf);
	    free(data);
	    return;
	}
	int nrows = PQntuples(res);
	if (nrows == 1) {
	    const char* update = "UPDATE nodes SET pubkey=$3 WHERE id=$1 AND token=$2";
	    const char* uparams[3];
	    uparams[0] = userid.c_str();
	    uparams[1] = token.c_str();
	    uparams[2] = pubkey.c_str();
	    std::cout << "Query: " << update << " params: " << userid << "<>" << token << "<>" << pubkey << std::endl;
	
	    res = PQexecParams(env->conn, update, 3, NULL, uparams, NULL, NULL, 0);
	    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
	        std::string html = ("{ \"status\":\"fail\" }");
	        evhttp_add_header(req->output_headers, "Content-Type", "application/json");
	        evbuffer_add_printf(OutBuf, "%s", html.c_str());
	        evhttp_send_reply(req, HTTP_OK, "", OutBuf);
	    } else {
	        std::string html = ("{ \"status\":\"ok\", \"runnerid\":\""+ userid +"\", \"token\":\""+token+"\" }");
	        evhttp_add_header(req->output_headers, "Content-Type", "application/json");
	        evbuffer_add_printf(OutBuf, "%s", html.c_str());
	        evhttp_send_reply(req, HTTP_OK, "", OutBuf);
	    }
	} else {
	    std::string html = ("{ \"status\":\"token not found\" }");
	    evhttp_add_header(req->output_headers, "Content-Type", "application/json");
	    evbuffer_add_printf(OutBuf, "%s", html.c_str());
	    evhttp_send_reply(req, HTTP_OK, "", OutBuf);
	}
	free(data);
    } else if (std::string(uri).compare("/task/pull") == 0) {
	struct evbuffer* buf = evhttp_request_get_input_buffer(req);
	size_t len = evbuffer_get_length(buf);
	char* data = (char*)malloc(len + 1);
	bzero(data, len+1);
	evbuffer_copyout(buf, data, len);
	json requestJson = json::parse(std::string(data));
	json object = requestJson["taskpull"];
	std::string runnerid = object["runnerid"];
	std::string token = object["token"];
	PGresult* res = NULL;
	const char* query = "SELECT * FROM nodes WHERE id=$1 AND token=$2;";
	const char* qparams[2];
	qparams[0] = runnerid.c_str();
	qparams[1] = token.c_str();
	res = PQexecParams(env->conn, query, 2, NULL, qparams, NULL, NULL, 0);
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
	    std::cout << "Can't select from db" << std::endl;
	    std::string html = ("{ \"data\":\"fail\" }");
	    evhttp_add_header(req->output_headers, "Content-Type", "application/json");
	    evbuffer_add_printf(OutBuf, "%s", html.c_str());
	    evhttp_send_reply(req, HTTP_OK, "", OutBuf);
	    free(data);
	    return;
	}
	int nrows = PQntuples(res);
	if (nrows == 1) {
	    const char* update = "UPDATE nodes SET last_run=NOW() WHERE id=$1 AND token=$2";
	    const char* uparams[2];
	    uparams[0] = runnerid.c_str();
	    uparams[1] = token.c_str();
	    std::cout << "Query: " << update << " params: " << runnerid << "<>" << token << std::endl;
	    res = PQexecParams(env->conn, update, 2, NULL, uparams, NULL, NULL, 0);
	    if (PQresultStatus(res) == PGRES_COMMAND_OK) {
		json* task = fetch_task();
		if (task == 0) {
		    std::string html = "{ \"data\":\"wait\" }";
		    evhttp_add_header(req->output_headers, "Content-Type", "application/json");
		    evbuffer_add_printf(OutBuf, "%s", html.c_str());
		    evhttp_send_reply(req, HTTP_OK, "", OutBuf);
		    free(data);
		} else {
		    json full = json::object();
		    full["format"] = *task;
		    full["data"] = "task";
		    std::string html = full.dump();
		    evhttp_add_header(req->output_headers, "Content-Type", "application/json");
		    evbuffer_add_printf(OutBuf, "%s", html.c_str());
		    evhttp_send_reply(req, HTTP_OK, "", OutBuf);
		    free(data);
		}
	    } else {
	        std::cout << "Can't update in db" << std::endl;
	        std::string html = ("{ \"data\":\"fail\" }");
	        evhttp_add_header(req->output_headers, "Content-Type", "application/json");
	        evbuffer_add_printf(OutBuf, "%s", html.c_str());
	        evhttp_send_reply(req, HTTP_OK, "", OutBuf);
	        free(data);
	        return;
	    }
	} else {
	    std::string html = "{ \"data\":\"badauth\" }";
	    evhttp_add_header(req->output_headers, "Content-Type", "application/json");
	    evbuffer_add_printf(OutBuf, "%s", html.c_str());
	    evhttp_send_reply(req, HTTP_OK, "", OutBuf);
	    free(data);
	}
    } else if (std::string(uri).compare("/task/push") == 0) {
	struct evbuffer* buf = evhttp_request_get_input_buffer(req);
	size_t len = evbuffer_get_length(buf);
	char* data = (char*)malloc(len + 1);
	bzero(data, len+1);
	evbuffer_copyout(buf, data, len);
	json responseJson = json::parse(std::string(data));
	
	std::string rawtosign = std::string(responseJson["task"]["attached-files-hashes"]["Dockerfile"]) + "\n" +
	    std::string(responseJson["task"]["attached-files-hashes"]["upload.creds"]) + "\n" +
	    std::string(responseJson["task"]["attached-files-hashes"]["scaling.yaml"]) + "\n" +
	    std::string(responseJson["task"]["attached-files-hashes"]["duplication.yaml"]) + "\n" +
	    std::string(responseJson["task"]["attached-files-hashes"]["urls_list"]["hash"]) + "\n" +
	//for key, value in format["task"]["unsigned"]["attached-files-raw"]["others"]:
	//    rawtosign = (rawtosign + value + "\n")
	    "mode=" + std::string(responseJson["task"]["mode"]) + "\n" +
	    "userid=" +std::string(responseJson["task"]["user"]["userid"]) + "\n" +
	    "taskid=" +std::string(responseJson["task"]["task-id"]) + "\n";
	
//	std::cout << "debug print rawtosign " << std::endl << rawtosign << std::endl;
	
	std::string uc(responseJson["task"]["server-signature"]);
//	std::cout << "debug print uc" << std::endl << uc << std::endl;
	const char *csign = uc.c_str();
	char *signpass = (char*)malloc(strlen(csign) + 1);
	bzero(signpass, strlen(csign)+1);
	strcpy(signpass, csign);
	bool is_verify = false;
	
	std::string path = "var/certs/servers/";
	for (const auto & entry : fs::directory_iterator(path)) {
//	    std::cout << entry.path() << std::endl;
	    std::ifstream t(entry.path());
	    std::string   serverPubKey((std::istreambuf_iterator<char>(t)), std::istreambuf_iterator<char>());
	    if (verify(rawtosign, signpass, serverPubKey)) {
		is_verify = true;
		break;
	    }
	}
	if (!is_verify) {
	    std::string html = ("{ \"status\":\"fail\", \"step\":\"server-sign\" }");
	    evhttp_add_header(req->output_headers, "Content-Type", "application/json");
	    evbuffer_add_printf(OutBuf, "%s", html.c_str());
	    evhttp_send_reply(req, HTTP_OK, "", OutBuf);
	}
	
	long long coordid = getCoordinatorId();
	responseJson["task"]["coordinator"]["coordinatorid"] = std::to_string(coordid);
	
	rawtosign = std::string(responseJson["task"]["attached-files-hashes"]["Dockerfile"]) + "\n" +
	    std::string(responseJson["task"]["attached-files-hashes"]["upload.creds"]) + "\n" +
	    std::string(responseJson["task"]["attached-files-hashes"]["scaling.yaml"]) + "\n" +
	    std::string(responseJson["task"]["attached-files-hashes"]["duplication.yaml"]) + "\n" +
	    std::string(responseJson["task"]["attached-files-hashes"]["urls_list"]["hash"]) + "\n" +
	//for key, value in format["task"]["unsigned"]["attached-files-raw"]["others"]:
	//    rawtosign = (rawtosign + value + "\n")
	    "mode=" + std::string(responseJson["task"]["mode"]) + "\n" +
	    "userid=" +std::string(responseJson["task"]["user"]["userid"]) + "\n" +
	    "taskid=" +std::string(responseJson["task"]["task-id"]) + "\n" +
	    "coordinatorid=" + std::to_string(coordid) + "\n" +
	    std::string(responseJson["task"]["server-signature"]) + "\n";
	
	responseJson["task"]["coordinator-signature"] = sign(rawtosign);
	
	PGresult* res = NULL;
	const char* count = "select count(*) from nodes WHERE last_run > NOW() - INTERVAL '2 minutes';";
	res = PQexec(env->conn, count);
	if (PQresultStatus(res) == PGRES_TUPLES_OK) {
	    char* count = PQgetvalue(res, 0, 0);
	    std::cout << "nodes online is " << count << std::endl;
	}
	
	//save task and create pull counter
	responseJson["task"]["unsigned"]["status"] = std::string("task");
	responseJson["task"]["unsigned"]["index"] =  json::object();
	responseJson["task"]["unsigned"]["index"]["n"] = 0;
	responseJson["task"]["unsigned"]["index"]["of"] = 0;
	
	int shards = getShardsCountFrom(
		responseJson["task"]["unsigned"]["attached-files-raw"]["urls_list"]["content"],
		responseJson["task"]["unsigned"]["attached-files-raw"]["urls_list"]["rows"],
		responseJson["task"]["attached-files-hashes"]["urls_list"]["hash"]);
	int duplication = getDuplicationCountFrom(
		responseJson["task"]["unsigned"]["attached-files-raw"]["duplication.yaml"],
		responseJson["task"]["attached-files-hashes"]["duplication.yaml"]);
	
	int runs = shards * duplication;
	responseJson["task"]["unsigned"]["index"]["of"] = runs;
	
	//create slots
	new_batch(responseJson, runs);
	std::cout << responseJson.dump() << std::endl;
	
	std::string html = ("{ \"status\":\"next\" }");
	evhttp_add_header(req->output_headers, "Content-Type", "application/json");
	evbuffer_add_printf(OutBuf, "%s", html.c_str());
	evhttp_send_reply(req, HTTP_OK, "", OutBuf);
    } else if (std::string(uri).compare("/task/report") == 0) {
	struct evbuffer* buf = evhttp_request_get_input_buffer(req);
	size_t len = evbuffer_get_length(buf);
	char* data = (char*)malloc(len + 1);
	bzero(data, len+1);
	evbuffer_copyout(buf, data, len);
	json responseJson = json::parse(std::string(data));
	
	json report = responseJson["report"];
	std::string runnerid = responseJson["runnerid"];
	std::string token = responseJson["token"];
	PGresult* res = NULL;
	const char* query = "SELECT * FROM nodes WHERE id=$1 AND token=$2;";
	const char* qparams[2];
	qparams[0] = runnerid.c_str();
	qparams[1] = token.c_str();
	res = PQexecParams(env->conn, query, 2, NULL, qparams, NULL, NULL, 0);
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
	    std::cout << "Can't select from db" << std::endl;
	    std::string html = ("{ \"data\":\"fail\" }");
	    evhttp_add_header(req->output_headers, "Content-Type", "application/json");
	    evbuffer_add_printf(OutBuf, "%s", html.c_str());
	    evhttp_send_reply(req, HTTP_OK, "", OutBuf);
	    free(data);
	    return;
	}
	
	std::cout << report.dump() << std::endl;
	
	long long coordid = getCoordinatorId();
	std::string rawtosign = std::string(report["task"]["attached-files-hashes"]["Dockerfile"]) + "\n" +
	    std::string(report["task"]["attached-files-hashes"]["upload.creds"]) + "\n" +
	    std::string(report["task"]["attached-files-hashes"]["scaling.yaml"]) + "\n" +
	    std::string(report["task"]["attached-files-hashes"]["duplication.yaml"]) + "\n" +
	    std::string(report["task"]["attached-files-hashes"]["urls_list"]["hash"]) + "\n" +
	//for key, value in format["task"]["unsigned"]["attached-files-raw"]["others"]:
	//    rawtosign = (rawtosign + value + "\n")
	    "mode=" + std::string(report["task"]["mode"]) + "\n" +
	    "userid=" +std::string(report["task"]["user"]["userid"]) + "\n" +
	    "taskid=" +std::string(report["task"]["task-id"]) + "\n" +
	    "coordinatorid=" + std::to_string(coordid) + "\n" +
	    std::string(report["task"]["server-signature"]) + "\n" + 
	    std::string(report["task"]["coordinator-signature"]) + "\n" + 
	    "runnerid=" + std::string(report["task"]["runner"]["runnerid"]) + "\n" +
	    "n=" + std::to_string((int)report["task"]["unsigned"]["index"]["n"]) + "\n" +
	    "of=" + std::to_string((int)report["task"]["unsigned"]["index"]["of"]) + "\n" +
	    std::string(report["task"]["runner-signature"]) + "\n";
	
	std::string signature = sign(rawtosign);
	
	set_done(
	    (int)report["task"]["unsigned"]["index"]["n"],
	    (int)report["task"]["unsigned"]["index"]["of"],
	    std::stoi(std::string(report["task"]["task-id"])),
	    std::stoi(std::string(report["task"]["runner"]["runnerid"])),
	    std::string(report["task"]["runner-signature"]),
	    signature
	);
	
	std::string html = ("{ \"report\":\"saved\" }");
	evhttp_add_header(req->output_headers, "Content-Type", "application/json");
	evbuffer_add_printf(OutBuf, "%s", html.c_str());
	evhttp_send_reply(req, HTTP_OK, "", OutBuf);
	free(data);
	return;
    } else if (std::string(uri).compare("/download/keys/coordinator") == 0) {
	std::string path = "var/certs/coordinators/";
	std::string response_json = ("{ \"coordinators\":[ ");
	for (const auto & entry : fs::directory_iterator(path)) {
	    std::cout << entry.path() << std::endl;
	    std::ifstream t(entry.path());
	    std::string publicKey((std::istreambuf_iterator<char>(t)),
	         std::istreambuf_iterator<char>());
	    publicKey = std::regex_replace(publicKey, std::regex("\n"), "\\n");
	    if (response_json.length() == std::string("{ \"coordinators\":[ ").length()) {
		response_json.append(" \"" + publicKey + "\"");
	    } else {
		response_json.append(", \"" + publicKey + "\"");
	    }
	}
	response_json.append("]}");
	evhttp_add_header(req->output_headers, "Content-Type", "application/json");
	evbuffer_add_printf(OutBuf, "%s", response_json.c_str());
	evhttp_send_reply(req, HTTP_OK, "", OutBuf);
    } else {
        if (query) {
            evbuffer_add_printf(OutBuf, "<html><body><center><h1>Not found</h1></center></body></html>");
        }
        evhttp_send_reply(req, 404, "", OutBuf);
    }


//    evbuffer_free(OutBuf);
  };
  evhttp_set_gencb(Server.get(), OnReq, env);
  if (event_dispatch() == -1) {
    std::cerr << "Failed to run messahe loop." << std::endl;
    return -1;
  }
  return 0;
}
