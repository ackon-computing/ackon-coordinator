
#define ERROR_getShardsCountFrom_BROKEN_ROWS_COUNT -1
#define ERROR_getShardsCountFrom_BROKEN_HASH -2

#define ERROR_getDuplicationCountFrom_BROKEN_HASH -2

int getShardsCountFrom(std::string content, int rows, std::string hash);
int getDuplicationCountFrom(std::string content, std::string hash);
