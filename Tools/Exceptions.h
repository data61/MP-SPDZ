#ifndef _Exceptions
#define _Exceptions

#include <exception>
#include <string>
#include <sstream>
#include <stdexcept>
using namespace std;

void exit_error(const string& message);

class not_implemented: public exception
    { virtual const char* what() const throw()
        { return "Case not implemented"; }
    };
class division_by_zero: public exception
    { virtual const char* what() const throw()
        { return "Division by zero"; }
    };
class invalid_plaintext: public exception
    { virtual const char* what() const throw()
        { return "Inconsistent plaintext space"; }
    };
class rep_mismatch: public exception
    { virtual const char* what() const throw()
        { return "Representation mismatch"; }
    };
class pr_mismatch: public exception
    { virtual const char* what() const throw()
        { return "Prime mismatch"; }
    };
class params_mismatch: public exception
    { virtual const char* what() const throw()
        { return "FHE params mismatch"; }
    };
class field_mismatch: public exception
    { virtual const char* what() const throw()
        { return "Plaintext Field mismatch"; }
    };
class level_mismatch: public exception
    { virtual const char* what() const throw()
        { return "Level mismatch"; }
    };
class invalid_length: public runtime_error
    {
    public:
      invalid_length(string msg = "") : runtime_error("Invalid length: " + msg) {}
    };
class invalid_commitment: public exception
    { virtual const char* what() const throw()
        { return "Invalid Commitment"; }
    };
class IO_Error: public exception
    {
      string ans;
      public:
      IO_Error(const string& m);
      ~IO_Error()throw() { }
      virtual const char* what() const throw()
        {
          return ans.c_str(); 
        }
    };
class broadcast_invalid: public exception
    { virtual const char* what() const throw()
        { return "Inconsistent broadcast at some point"; }
    };
class bad_keygen: public runtime_error
    {
      public:
      bad_keygen(string m) : runtime_error("KeyGen has gone wrong: "+m) {}
    };
class bad_enccommit:  public exception
    { virtual const char* what() const throw()
        { return "Error in EncCommit"; }
    };
class invalid_params:  public exception
    { virtual const char* what() const throw()
        { return "Invalid Params"; }
    };
class bad_value: public runtime_error
    {
      public:
      bad_value(string msg = "Some value is wrong somewhere") : runtime_error(msg) {}
    };
class Offline_Check_Error: public runtime_error
    {
      public:
      Offline_Check_Error(string m) :
          runtime_error("Offline-Check-Error : " + m) {}
    };
class mac_fail:  public bad_value
    {
      public:
      mac_fail(string msg = "MacCheck Failure") : bad_value(msg) {}
    };
class consistency_check_fail:  public exception
    { virtual const char* what() const throw()
        { return "OT consistency check failed"; }
    };
class invalid_program:  public exception
    { virtual const char* what() const throw()
        { return "Invalid Program"; }
    };
class file_error:  public exception
    {
      string ans;
      public:
      file_error(const string& m);
      ~file_error()throw() { }
      virtual const char* what() const throw()
        {
          return ans.c_str();
        }
    };
class end_of_file: public exception
    { string filename, context, ans;
      public:
      end_of_file(string pfilename="no filename", string pcontext="") : 
        filename(pfilename), context(pcontext)
        {
          ans="End of file when reading ";
          ans+=filename;
          ans+=" ";
          ans+=context;
        }
      ~end_of_file()throw() { }
      virtual const char* what() const throw()
        {
          return ans.c_str();
        }
    };
class file_missing:  public exception
    { string filename, context, ans;
      public:
      file_missing(string pfilename="no filename", string pcontext="") : 
        filename(pfilename), context(pcontext)
        {
          ans="File missing : ";
          ans+=filename;
          ans+=" ";
          ans+=context;
        }
      ~file_missing()throw() { }
      virtual const char* what() const throw()
        {
          return ans.c_str();
        }
    };    
class Processor_Error: public exception
    { string msg;
      public:
      Processor_Error(const string& m);
      Processor_Error(const char* m);
      ~Processor_Error()throw() { }
      virtual const char* what() const throw()
        {
          return msg.c_str();
        }
    };

class max_mod_sz_too_small : public exception
    {
      string msg;
      public:
      max_mod_sz_too_small(int len)
        { stringstream out;
          out << "MAX_MOD_SZ too small for desired bit length of p, "
                  << "must be at least ceil(len(p)/len(word)), "
                  << "in this case: " << len;
          msg = out.str();
        }
      ~max_mod_sz_too_small() throw() {}
      virtual const char* what() const throw()
        {
          return msg.c_str();
        }
    };
class crash_requested: public exception
    { virtual const char* what() const throw()
        { return "Crash requested by program"; }
    };
class memory_exception : public exception {};
class how_would_that_work : public exception {};
class not_enough_to_buffer : public runtime_error
{
public:
    not_enough_to_buffer(const string& type, const string& filename);
};
class needs_cleaning : public exception {};

class closed_connection : public exception
{
    const char* what() const throw()
    {
        return "Connection closed down. "
            "This is most likely due to a problem on the other side. "
            "If there's no error message on the other side, it might be "
            "due to a lack of memory. See "
            "https://mp-spdz.readthedocs.io/en/latest/troubleshooting.html#crash-without-error-message-killed-or-bad-alloc "
            "for possible remedies.";
    }
};

class no_singleton : public runtime_error
{
public:
    no_singleton(string msg = "no singleton") :
            runtime_error(msg)
    {
    }
};

class ran_out : public exception
{
    const char* what() const throw()
    {
        return "insufficient preprocessing";
    }
};

class bigint;

class wrong_gfp_size : public runtime_error
{
public:
    wrong_gfp_size(const char* name, const bigint& p, const char* symbol,
            int n_limbs);
};

class mac_key_error: public runtime_error
{
public:
    mac_key_error(string filename) :
            runtime_error("error loading MAC key from " + filename)
    {
    }
};

class overflow : public runtime_error
{
public:
    overflow(const string& name, size_t i, size_t n);
};

class unknown_input_type : public runtime_error
{
public:
    unknown_input_type(int type);
};

class invalid_opcode : public runtime_error
{
public:
    invalid_opcode(int opcode);
};

class input_error : public exception
{
    string msg;

public:
    input_error(const char* name, const string& filename,
            istream& input_file, size_t input_counter);

    const char* what() const throw()
    {
        return msg.c_str();
    }
};

class signature_mismatch : public runtime_error
{
public:
    signature_mismatch(const string& filename, bool has_mac = false);
};

class insufficient_memory : public runtime_error
{
public:
    insufficient_memory(size_t size, const string& type);
};

class gf2n_not_supported : public runtime_error
{
public:
    gf2n_not_supported(int n, string options = "");
};

class setup_error : public runtime_error
{
public:
    setup_error(const string& error);
};

class prep_setup_error : public setup_error
{
public:
    prep_setup_error(const string& error, int nplayers, const string& fake_opts);
};

class insufficient_shares : public runtime_error
{
public:
    insufficient_shares(int expected, int actual, exception& e);
};

class persistence_error : public runtime_error
{
public:
    persistence_error(const string& error);
};

class bytecode_error : public runtime_error
{
public:
    bytecode_error(const string& error);
};

typedef bytecode_error Invalid_Instruction;

class no_dynamic_memory : public runtime_error
{
public:
    no_dynamic_memory();
};

class field_too_small : public runtime_error
{
public:
    field_too_small(int length, int security);
};

#endif
