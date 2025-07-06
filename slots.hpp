#include "json.hpp"

#define task_status_QUEUED 0
#define task_status_FETCHED 1
#define task_status_DONE 2

#define batch_status_RUNNING 0
#define batch_status_DONE 1

using json = nlohmann::json;

typedef struct {
    int batch_id;

    int done_count;
    int fetched_count;
    int of;
    int status;
} batch;

typedef struct {
    batch* b;
    int n;
    int of;
    json data;
    int status;

    int runnerid;
    std::string* runnerSignature;
} task;

void init_slots();
void new_batch(json data, int of);
json* fetch_task();
void set_done(int n, int of, int batch_id, int runnerid, std::string runnerSignature, std::string coordinatorStatusSignature);
