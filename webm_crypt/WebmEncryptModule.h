#pragma once

#include "WebmCryptCommon.h"

namespace crypto {
	class SymmetricKey;
}

namespace webm_crypt_dll {

	class WebmEncryptModule
	{
	protected:
		WebmEncryptModule(const std::string& secret, uint64_t initial_iv);
		~WebmEncryptModule();

	public:
		WECAPI static WebmEncryptModule* Create(const std::string& secret, uint64_t initial_iv);
		WECAPI static void Destroy(WebmEncryptModule* instance);
		WECAPI bool Init();
		WECAPI bool ProcessData(const uint8_t* plaintext, size_t size, uint8_t* ciphertext, size_t* ciphertext_size);
		WECAPI void set_do_not_encrypt(bool flag);
		WECAPI const char* GetError();

	private:
		bool do_not_encrypt_;
		std::unique_ptr<crypto::SymmetricKey> key_;
		uint64_t next_iv_;
		std::string error_message_;
	};
}