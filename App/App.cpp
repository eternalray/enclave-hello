#include <iostream>
#include <string>
#include <cstring>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "sgx_urts.h"
#include "Enclave_u.h"

using namespace std;

const string ENCLAVE_NAME = "enclave.signed.so";
const string ENCLAVE_TOKEN = "enclave.token";
const string SEALED_DATA = "sealed.data";

sgx_enclave_id_t global_eid = 0;

/* Ocalls */

void ocall_print(const char* str){
  printf("%s\n", str);
}

void print_error_message(sgx_status_t ret){
  printf("SGX error code : %d\n", ret);
}

int initializeEnclave(){
  cout << "initializing enclave..." << endl;

  const char* token_path = ENCLAVE_TOKEN.c_str();
  sgx_launch_token_t token = {0};
  size_t token_size = sizeof(sgx_launch_token_t);
  int updated = 0;
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;

  FILE* fp = fopen(token_path, "rb");
  if(fp == NULL && (fp = fopen(token_path, "wb")) == NULL)
    cout << "WARNING : Failed to load token " << token_path << endl;

  if(fp != NULL){
    size_t read_num = fread(token, 1, token_size, fp);
    if(read_num != 0 && read_num != token_size){
      memset(&token, 0x0, token_size);
      cout << "WARNING : Invalid launch token read " << token_path << endl;
    }
  }

  ret = sgx_create_enclave(ENCLAVE_NAME.c_str(), 1, &token, &updated, &global_eid, NULL);
  if(ret != SGX_SUCCESS){
    cout << "Creating enclave failed. Aborting..." << endl;
    print_error_message(ret);
    if(fp != NULL) fclose(fp);
    return -1;
  }

  if(updated == 0 || fp == NULL){
    if(fp != NULL) fclose(fp);
    return 0;
  }

  fp = freopen(token_path, "wb", fp);
  if(fp == NULL) return 0;
  size_t write_num = fwrite(token, 1, token_size, fp);
  if(write_num != token_size)
    cout << "WARNING : Failed to save launch token." << endl;
  fclose(fp);
  return 0;

}

int main(){
  unsigned int branch;

  cout << "user input\n1.input string to enclave\n2.load string from sealed data" << endl;
  cin >> branch;

  switch(branch){
    case 1:
    {
      if(initializeEnclave()){
        cout << "Failed to initialize enclave" << endl;
        return -1;
      }

      string inputString;
      cout << "input string : ";
      cin >> inputString;
      cout << "got " << inputString << endl;
      sgx_status_t status = save_string(global_eid, inputString.c_str());
      cout << status << endl;

      if(status != SGX_SUCCESS)
      cout << "Something is wrong" << endl;

      cout << "Sealing data..." << endl;
      size_t sealed_size = sizeof(sgx_sealed_data_t) + inputString.length();
      uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);

      sgx_status_t ecall_status;
      status = seal(global_eid, &ecall_status,
        (uint8_t*)inputString.c_str(), inputString.length(),
        (sgx_sealed_data_t*)sealed_data, sealed_size);

        FILE* fp = fopen(SEALED_DATA.c_str(), "wb");
        if(fp == NULL) return 0;
        size_t write_num = fwrite(sealed_data, 1, sealed_size, fp);
        if(write_num != sealed_size)
        cout << "Sealing failed" << endl;
        fclose(fp);



        if(status != SGX_SUCCESS)
        cout << "Something is wrong" << endl;


        cout << "Terminating..." << endl;
        free(sealed_data);
        break;

    }

    case 2:
    {
      if(initializeEnclave()){
        cout << "Failed to initialize enclave" << endl;
        return -1;
      }
      cout << "Loading string..." << endl;

      struct stat buffer;
      int i;
      i = stat(SEALED_DATA.c_str(), &buffer);

      uint8_t* sealed_data = (uint8_t*)malloc(buffer.st_size);
      uint8_t* unsealed = (uint8_t*)malloc(1024);

      FILE* fp = fopen(SEALED_DATA.c_str(), "rb");
      size_t read_num = fread(sealed_data, 1, buffer.st_size, fp);
      if(read_num != buffer.st_size)
        cout << "Something is wrong" << endl;
      fclose(fp);

      sgx_status_t ecall_status;
      ecall_status = unseal(global_eid, &ecall_status,
        (sgx_sealed_data_t*)sealed_data, buffer.st_size,
        unsealed, 1024);
      if(ecall_status != SGX_SUCCESS)
        cout << "Sealing failed. Aborting..." << endl;

      string s((const char*)unsealed);

      cout << "Unsealed string : " << s << endl;

      cout << "Terminating..." << endl;
      free(sealed_data);

    }




  };


}
