#ifndef _SHA1
#define _SHA1

#include <sodium.h>
#include <vector>
using namespace std;

#include "octetStream.h"

class Hash
{
	crypto_generichash_state* state;
	octetStream tmp;

public:
	static const int hash_length = crypto_generichash_BYTES;

	unsigned size;

	Hash();
	~Hash();

	void reset();

	void update(const void *dataIn, unsigned long len)
	{
		crypto_generichash_update(state, (unsigned char*)dataIn, len);
		size += len;
	}
	void update(const octetStream& os);
	template<class T>
	void update(const T& x)
	{
	    update(x.get_ptr(), x.size());
	}
	template<class T>
	void update(const vector<T>& v, const vector<int>& bit_lengths)
	{
	    assert(v.size() == bit_lengths.size());
	    tmp.reset_write_head();
	    tmp.reserve(v.size() * sizeof(T));
	    for (size_t i = 0; i < v.size(); i++)
	        v[i].pack(tmp, bit_lengths[i]);
	    tmp.append(0);
	    update(tmp);
	}
	void update(const string& str);

	void final(unsigned char hashout[hash_length])
	{
		final(hashout, hash_length);
	}
	void final(unsigned char* hashout, size_t length)
	{
	    assert(crypto_generichash_final(state, hashout, length) == 0);
	    reset();
	}
	void final(octetStream& os);
	void append_final(octetStream& os);
	octetStream final();

	bool matches(octetStream& os);
};

void hash_update(Hash *ctx, const void *dataIn, unsigned long len);

#endif
