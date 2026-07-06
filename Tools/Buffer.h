/*
 * Buffer.h
 *
 */

#ifndef TOOLS_BUFFER_H_
#define TOOLS_BUFFER_H_

#include <fstream>
#include <iostream>
#include <assert.h>
using namespace std;

#include "Math/field_types.h"
#include "Tools/time-func.h"
#include "Tools/octetStream.h"
#include "Tools/pprint.h"
#include "Processor/OnlineOptions.h"

#ifndef BUFFER_SIZE
#define BUFFER_SIZE 101
#endif

class BufferBase
{
protected:
    static bool rewind;

    ifstream* file;
    int next;
    string data_type;
    string field_type;
    Timer timer;
    int tuple_length;
    string filename;
    int header_length;

    virtual int element_length() = 0;

public:
    bool eof;

    BufferBase() : file(0), next(BUFFER_SIZE),
            tuple_length(-1), header_length(0), eof(false) {}
    ~BufferBase() {}
    virtual ifstream* open() = 0;
    void setup(ifstream* f, int length, const string& filename,
            const char* type = "", const string& field = {});
    void seekg(int pos);
    bool is_up() { return file != 0; }
    bool is_pipe();
    void try_rewind();
    void prune();
    void purge();
    void check_tuple_length(int tuple_length);
};


template <class T, class U>
class Buffer : public BufferBase
{
    T buffer[BUFFER_SIZE];

    void read(char* read_buffer);

    int element_length() { return T::size(); }

public:
    virtual ~Buffer();
    virtual ifstream* open();
    void input(U& a);
    void fill_buffer();
};

template<class T>
octetStream file_signature(const typename T::mac_type& mac_key)
{
    octetStream res(T::type_string());
    T::specification(res);
    if (T::has_mac)
    {
        if (mac_key == typename T::mac_type())
        {
            assert(T::get_mac_key() != 0);
            T::get_mac_key().pack(res);
        }
        else
            mac_key.pack(res);
    }
    return res;
}

template<class T>
octetStream file_signature(true_type)
{
    octetStream res(T::type_string());
    T::specification(res);
    return res;
}

template<class T>
octetStream file_signature(false_type)
{
    return file_signature<T>(typename T::mac_type());
}

template<class T>
octetStream file_signature()
{
    return file_signature<T>(T::is_clear);
}

template<class T>
bool has_mac(true_type)
{
    return false;
}

template<class T>
bool has_mac(false_type)
{
    return T::has_mac;
}

template<class T>
octetStream check_file_signature(ifstream& file, const string& filename)
{
    octetStream file_spec;
    try
    {
        file_spec.input(file);
    }
    catch (bad_alloc&)
    {
        throw signature_mismatch(filename);
    }
    catch (IO_Error&)
    {
        throw signature_mismatch(filename);
    }
    if (file_signature<T>() != file_spec)
    {
#ifndef DEBUG_FILE_SIGNATURE
        if (OnlineOptions::singleton.has_option("debug_file_signature"))
#endif
        {
            auto exp = file_signature<T>();
            pprint_bytes("found   ", file_spec.get_data(), file_spec.get_length());
            pprint_bytes("expected", exp.get_data(), exp.get_length());
        }
        throw signature_mismatch(filename, has_mac<T>(T::is_clear));
    }
    return file_spec;
}

template<class U, class V, class W = U>
class BufferOwner : public Buffer<U, V>
{
    ifstream* file;

public:
    BufferOwner() :
            file(0)
    {
    }

    BufferOwner(const BufferOwner& other) :
            file(0)
    {
        *this = other;
    }

    ~BufferOwner()
    {
        close();
    }

    BufferOwner& operator=(const BufferOwner& other)
    {
        assert(other.file == 0);
        file = 0;
        Buffer<U, V>::operator=(other);
        return *this;
    }

    ifstream* open()
    {
        file = new ifstream(this->filename, ios::in | ios::binary);
        BufferBase::file = file;
        if (file->good())
        {
            auto file_spec = check_file_signature<W>(*file, this->filename);
            this->header_length = file_spec.get_length()
                    + sizeof(file_spec.get_length());
        }
        return file;
    }

    void setup(const string& filename, int tuple_length,
            const char* data_type = "")
    {
        Buffer<U, V>::setup(file, tuple_length, filename, data_type,
              U::type_string());
    }

    void setup(const string& filename, int tuple_length,
            const string& type_string, const char* data_type = "")
    {
        Buffer<U, V>::setup(file, tuple_length, filename, data_type,
                type_string);
    }

    void close()
    {
        if (file)
            delete file;
        file = 0;
    }
};

template<class T, class U>
inline Buffer<T, U>::~Buffer()
{
#ifdef VERBOSE
    if (timer.elapsed() && data_type.size())
        cerr << T::type_string() << " " << data_type << " reading: "
                << timer.elapsed() << endl;
#endif
}

template<class T, class U>
inline void Buffer<T, U>::fill_buffer()
{
  if (T::size() == sizeof(T))
    {
      // read directly
      read((char*)buffer);
    }
  else
    {
      char* read_buffer = new char[BUFFER_SIZE * T::size()];
      read(read_buffer);
      //memset(buffer, 0, sizeof(buffer));
      for (int i = 0; i < BUFFER_SIZE; i++)
        buffer[i].assign(&read_buffer[i*T::size()]);
      delete[] read_buffer;
    }
}

template<class T, class U>
ifstream* Buffer<T, U>::open()
{
    throw IO_Error(T::type_string() + " buffer not set up");
}

template<class T, class U>
inline void Buffer<T, U>::read(char* read_buffer)
{
    int size_in_bytes = T::size() * BUFFER_SIZE;
    int n_read = 0;
    timer.start();
    if (not file)
        file = open();
    do
    {
        file->read(read_buffer + n_read, size_in_bytes - n_read);
        n_read += file->gcount();
#ifdef DEBUG_BUFFER
        fprintf(stderr, "read %d\n", n_read);
#endif
        if (file->eof())
        {
            try_rewind();
        }
        if (file->fail())
          {
            stringstream ss;
            ss << "IO problem when buffering " << T::type_string();
            if (data_type.size())
              ss << " " << data_type;
            ss << " from " << filename;
            throw file_error(ss.str());
          }
    }
    while (n_read < size_in_bytes);
    timer.stop();
}

template <class T, class U>
inline void Buffer<T,U>::input(U& a)
{
#ifdef DEBUG_BUFFER
    fprintf(stderr, "next is %d\n", next);
#endif
    if (next == BUFFER_SIZE)
    {
        fill_buffer();
        next = 0;
    }

    a = buffer[next];
    next++;
}

#endif /* TOOLS_BUFFER_H_ */
