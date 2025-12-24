/*
 * BaseMachine.cpp
 *
 */

#include "BaseMachine.h"
#include "OnlineOptions.h"
#include "Math/Setup.h"
#include "Tools/Bundle.h"

#include "Instruction.hpp"
#include "Protocols/ShuffleSacrifice.hpp"

#include <iostream>
#include <sodium.h>
#include <regex>
using namespace std;

BaseMachine* BaseMachine::singleton = 0;
thread_local int BaseMachine::thread_num;
thread_local OnDemandOTTripleSetup BaseMachine::ot_setup;
thread_local const Program* BaseMachine::program = 0;

void print_usage(ostream& o, const char* name, size_t capacity)
{
  if (capacity)
    o << name << "=" << capacity << " ";
}

BaseMachine& BaseMachine::s()
{
  if (singleton)
    return *singleton;
  else
    throw runtime_error("no BaseMachine singleton");
}

bool BaseMachine::has_program()
{
  return has_singleton() and not s().progs.empty();
}

DataPositions BaseMachine::get_offline_data_used()
{
  if (program)
    return program->get_offline_data_used();
  else
    return s().progs[0].get_offline_data_used();
}

int BaseMachine::edabit_bucket_size(int n_bits)
{
  size_t usage = 0;
  if (has_program())
    usage = get_offline_data_used().total_edabits(n_bits);
  return bucket_size(usage);
}

int BaseMachine::triple_bucket_size(DataFieldType type)
{
  size_t usage = 0;
  if (has_program())
    usage = get_offline_data_used().files[type][DATA_TRIPLE];
  return bucket_size(usage);
}

int BaseMachine::bucket_size(size_t usage)
{
  int res = OnlineOptions::singleton.bucket_size;
  int min = res;

  if (usage)
    {
      res = 5;
      for (int B = res; B >= min; B--)
        if (ShuffleSacrifice(B).minimum_n_outputs() > usage * 1.1)
          break;
        else
          res = B;
    }

  if (OnlineOptions::singleton.has_option("debug_batch_size"))
    fprintf(stderr, "bucket_size=%d usage=%zu\n", res, usage);

  return res;
}

int BaseMachine::matrix_batch_size(int n_rows, int n_inner, int n_cols)
{
  int limit = max(1., 1e6 / (max(n_rows * n_inner, n_inner * n_cols)));
  unsigned res = min(limit, OnlineOptions::singleton.batch_size);
  if (has_program())
    res = min(res, (unsigned) matrix_requirement(n_rows, n_inner, n_cols));
  return res;
}

int BaseMachine::matrix_requirement(int n_rows, int n_inner, int n_cols)
{
  if (has_program())
    {
      auto res = get_offline_data_used().matmuls[
          {n_rows, n_inner, n_cols}];
      if (res)
        return res;
      else
        return -1;
    }
  else
    return -1;
}

bool BaseMachine::allow_mulm()
{
  return singleton and singleton->relevant_opts.find("no_mulm") != string::npos;
}

BaseMachine::BaseMachine() :
    nthreads(0), multithread(false), nan_warning(0), mini_warning(0)
{
  if (sodium_init() == -1)
    throw runtime_error("couldn't initialize libsodium");
  if (not singleton)
    singleton = this;
}

void BaseMachine::load_schedule(const string& progname, bool load_bytecode)
{
  this->progname = progname;
  string fname = "Programs/Schedules/" + progname + ".sch";
#ifdef DEBUG_FILES
  cerr << "Opening file " << fname << endl;
#endif
  ifstream inpf;
  inpf.open(fname);
  if (inpf.fail()) { throw file_error("Missing '" + fname + "'. Did you compile '" + progname + "'?"); }

  int nprogs;
  inpf >> nthreads;
  inpf >> nprogs;

  if (inpf.fail())
    throw file_error("Error reading " + fname);

#ifdef DEBUG_FILES
  cerr << "Number of threads I will run in parallel = " << nthreads << endl;
  cerr << "Number of program sequences I need to load = " << nprogs << endl;
#endif

  bc_filenames.clear();

  // Load in the programs
  string threadname;
  for (int i=0; i<nprogs; i++)
    { inpf >> threadname;
      size_t split = threadname.find_last_of(":");
      long expected = -1;
      if (split != string::npos)
        {
          expected = atoi(threadname.substr(split + 1).c_str());
          threadname = threadname.substr(0, split);
        }

      string filename = "Programs/Bytecode/" + threadname + ".bc";
      bc_filenames.push_back(filename);
      if (load_bytecode)
        {
#ifdef DEBUG_FILES
          cerr << "Loading program " << i << " from " << filename << endl;
#endif
          long size = load_program(threadname, filename);
          if (expected >= 0 and expected != size)
            {
              stringstream os;
              os << "broken bytecode file, found " << size
                  << " instructions, expected " << expected;
              throw runtime_error(os.str());
            }
        }

    }

  for (auto i : {1, 0, 0})
    {
      int n;
      inpf >> n;
      if (n != i)
        throw runtime_error("old schedule format not supported");
    }

  inpf.get();
  getline(inpf, compiler);
  getline(inpf, domain);
  getline(inpf, relevant_opts);
  getline(inpf, security);
  getline(inpf, gf2n);
  getline(inpf, expected_communication);
  inpf.close();
}

void BaseMachine::print_compiler()
{
  if (compiler.size() != 0 and OnlineOptions::singleton.verbose)
    cerr << "Compiler: " << compiler << endl;
}

size_t BaseMachine::load_program(const string& threadname,
    const string& filename)
{
  (void)threadname;
  (void)filename;
  throw not_implemented();
}

void BaseMachine::time()
{
  cout << "Elapsed time: " << timer[0].elapsed() << endl;
}

void BaseMachine::start(int n)
{
  cout << "Starting timer " << n << " at " << timer[n].elapsed()
    << " (" << timer[n] << ")"
    << " after " << timer[n].idle() << endl;
  timer[n].start(total_comm());
}

void BaseMachine::stop(int n)
{
  timer[n].stop(total_comm());
  cout << "Stopped timer " << n << " at " << timer[n].elapsed() << " ("
      << timer[n] << ")" << endl;
}

void BaseMachine::print_timers()
{
  cerr << "The following benchmarks are ";
  if (OnlineOptions::singleton.live_prep)
    cerr << "in";
  else
    cerr << "ex";
  cerr << "cluding preprocessing (offline phase)." << endl;
  cerr << "Time = " << timer[0].elapsed() << " seconds " << endl;
  timer.erase(0);
  for (auto it = timer.begin(); it != timer.end(); it++)
    cerr << "Time" << it->first << " = " << it->second.elapsed() << " seconds ("
        << it->second << ")" << endl;
}

string BaseMachine::memory_filename(const string& type_short, int my_number)
{
  return PREP_DIR "Memory-" + type_short + "-P" + to_string(my_number);
}

string BaseMachine::get_domain(string progname)
{
  return get_basics(progname).domain;
}

BaseMachine BaseMachine::get_basics(string progname)
{
  if (singleton and s().progname == progname)
    return s();

  auto backup = singleton;
  BaseMachine machine;
  singleton = backup;
  machine.load_schedule(progname, false);
  return machine;
}

int BaseMachine::ring_size_from_schedule(string progname)
{
  string domain = get_domain(progname);
  if (domain.substr(0, 2).compare("R:") == 0)
  {
    return stoi(domain.substr(2));
  }
  else
    return 0;
}

int BaseMachine::prime_length_from_schedule(string progname)
{
  string domain = get_domain(progname);
  if (domain.substr(0, 4).compare("lgp:") == 0)
    return stoi(domain.substr(4));
  else
    return 0;
}

int BaseMachine::gf2n_length_from_schedule(string progname)
{
  string domain = get_basics(progname).gf2n;
  if (domain.substr(0, 4).compare("lg2:") == 0)
    return stoi(domain.substr(4));
  else
    return 0;
}

bigint BaseMachine::prime_from_schedule(string progname)
{
  string domain = get_domain(progname);
  if (domain.substr(0, 2).compare("p:") == 0)
    return bigint(domain.substr(2));
  else
    return 0;
}

int BaseMachine::security_from_schedule(string progname)
{
  string sec = get_basics(progname).security;
  if (sec.substr(0, 4).compare("sec:") == 0)
    return stoi(sec.substr(4));
  else
    return 0;
}

NamedCommStats BaseMachine::total_comm()
{
  return queues.total_comm();
}

void BaseMachine::set_thread_comm(const NamedCommStats& stats)
{
  auto queue = queues.at(BaseMachine::thread_num);
  assert(queue);
  queue->set_comm_stats(stats);
}

void BaseMachine::print_global_comm(Player& P, const NamedCommStats& stats)
{
  Bundle<octetStream> bundle(P);
  bundle.mine.store(stats.sent);
  P.Broadcast_Receive_no_stats(bundle);
  long long global = 0;
  for (auto& os : bundle)
    global += os.get_int(8);
  cerr << "Global data sent = " << global / 1e6 << " MB (all parties)" << endl;

  smatch what;
  regex comm_regexp("online:([0-9]*) offline:([0-9]*) n_parties:([0-9]*)");
  if (regex_search(expected_communication, what, comm_regexp))
    {
      long long expected = stoll(what[1]) + stoll(what[2]);
      int n_parties = stoi(what[3]);
      if (expected and n_parties != P.num_players())
        {
          cerr << "Wrong number of parties in compiler's expectation: "
              << n_parties << endl;
        }
      else if (expected)
        {
          double over = round(100. * (global - expected) / expected);
          if (over >= 5)
            cerr
                << "Actual communication exceeds the compiler's expectation by "
                << over << " percent." << endl;
          if (over < 0)
            {
              if (OnlineOptions::singleton.has_option("overestimate"))
                cerr << "Actual communication is below the compiler's "
                "expectation by " << -over << " percent." << endl;
              else
                cerr << "The compiler overestimated the communication." << endl;
            }
        }
    }
}

void BaseMachine::print_comm(Player& P, const NamedCommStats& comm_stats)
{
  size_t rounds = 0;
  for (auto& x : comm_stats)
    if (x.first.find("transmission") == string::npos)
      rounds += x.second.rounds;
  cerr << "Data sent = " << comm_stats.sent / 1e6 << " MB in ~" << rounds
      << " rounds (party " << P.my_num() << " only";
  if (multithread)
    cerr << "; rounds counted double due to multi-threading";
  if (not OnlineOptions::singleton.verbose)
    cerr << "; use '-v' for more details";
  cerr << ")" << endl;

  print_global_comm(P, comm_stats);
}

void BaseMachine::add_one_off(const NamedCommStats& comm)
{
  if (has_singleton())
    s().one_off_comm += comm;
}
