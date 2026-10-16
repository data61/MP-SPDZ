/*
 * DataPositions.cpp
 *
 */

#include "Data_Files.h"

#include <iomanip>
#include <numeric>

const char* DataPositions::field_names[] = { "int", "gf2n", "bit" };

const int DataPositions::tuple_size[N_DTYPE] = { 3, 2, 1, 2 };

DataPositions::DataPositions(int num_players)
{
  set_num_players(num_players);
}

DataPositions::~DataPositions()
{
}

void DataPositions::reset()
{
  *this = DataPositions(num_players());
}

void DataPositions::set_num_players(int num_players)
{
  files = {};
  inputs.resize(num_players, {});
}

void DataPositions::count(DataFieldType type, DataTag tag, int n)
{
  extended[type][tag] += n;
}

void DataPositions::count_edabit(bool strict, int n_bits)
{
  edabits[{strict, n_bits}]++;
}

void DataPositions::increase(const DataPositions& delta)
{
  inputs.resize(max(inputs.size(), delta.inputs.size()), {});
  for (unsigned int field_type = 0; field_type < N_DATA_FIELD_TYPE; field_type++)
    {
      for (unsigned int dtype = 0; dtype < N_DTYPE; dtype++)
        files[field_type][dtype] += delta.files[field_type][dtype];
      for (unsigned int j = 0; j < delta.inputs.size(); j++)
        inputs[j][field_type] += delta.inputs[j][field_type];

      map<DataTag, long long>::const_iterator it;
      const map<DataTag, long long>& delta_ext = delta.extended[field_type];
      for (it = delta_ext.begin(); it != delta_ext.end(); it++)
          extended[field_type][it->first] += it->second;
    }
  for (auto it = delta.edabits.begin(); it != delta.edabits.end(); it++)
    edabits[it->first] += it->second;
}

DataPositions& DataPositions::operator-=(const DataPositions& delta)
{
  inputs.resize(max(inputs.size(), delta.inputs.size()), {});
  for (unsigned int field_type = 0; field_type < N_DATA_FIELD_TYPE;
      field_type++)
    {
      for (unsigned int dtype = 0; dtype < N_DTYPE; dtype++)
        files[field_type][dtype] -= delta.files[field_type][dtype];
      for (unsigned int j = 0; j < delta.inputs.size(); j++)
        inputs[j][field_type] -= delta.inputs[j][field_type];

      map<DataTag, long long>::const_iterator it;
      const map<DataTag, long long> &delta_ext = delta.extended[field_type];
      for (it = delta_ext.begin(); it != delta_ext.end(); it++)
        extended[field_type][it->first] -= it->second;
    }
  for (auto it = delta.edabits.begin(); it != delta.edabits.end(); it++)
    edabits[it->first] -= it->second;
  return *this;
}

DataPositions& DataPositions::operator/=(int divisor)
{
  for (unsigned int field_type = 0; field_type < N_DATA_FIELD_TYPE;
      field_type++)
    {
      for (unsigned int dtype = 0; dtype < N_DTYPE; dtype++)
        files[field_type][dtype] /= divisor;
      for (unsigned int j = 0; j < inputs.size(); j++)
        inputs[j][field_type] /= divisor;

      for (auto it = extended[field_type].begin();
          it != extended[field_type].end(); it++)
        it->second /= divisor;
    }
  for (auto it = edabits.begin(); it != edabits.end(); it++)
    it->second /= divisor;
  return *this;
}

DataPositions DataPositions::operator-(const DataPositions& other) const
{
  DataPositions res = *this;
  res -= other;
  return res;
}

DataPositions DataPositions::operator+(const DataPositions& other) const
{
  DataPositions res = *this;
  res.increase(other);
  return res;
}

void DataPositions::print_cost() const
{
  ifstream file("cost");
  bool print_verbose = file.good();
  double total_cost = 0;
  for (int i = 0; i < N_DATA_FIELD_TYPE; i++)
    {
      if (accumulate(files[i].begin(), files[i].end(), 0) > 0)
        cerr << "  Type " << field_names[i] << endl;
      bool reading_field = true;
      for (int j = 0; j < N_DTYPE; j++)
        process_line(files[i][j], dtype_names[j], file, print_verbose, total_cost, reading_field);

      long long n_inputs = 0;
      stringstream ss;
      ss << " (";
      for (auto& x : inputs)
        {
          n_inputs += x[i];
          ss << x[i] << " ";
        }
      string s = ss.str();
      s.pop_back();
      s += ")";
      process_line(n_inputs, "Input tuples", file, print_verbose, total_cost, reading_field, s);

      for (map<DataTag, long long>::const_iterator it = extended[i].begin();
          it != extended[i].end(); it++)
        {
          cerr.fill(' ');
          cerr << setw(27) << it->second << " " << setw(14) << it->first.get_string() << endl;
        }
    }

  if (total_cost > 0)
    cerr << "Total cost: " << total_cost << endl;

  if (not edabits.empty())
    cerr << "  edaBits" << endl;
  for (auto it = edabits.begin(); it != edabits.end(); it++)
    {
      if (it->second)
        {
          if (print_verbose)
              cerr << setw(13) << "";
          cerr << "    " << setw(10) << it->second << " of length "
                  << it->first.second;
          if (it->first.first)
              cerr << " (strict)";
          cerr << endl;
        }
    }
}

void DataPositions::process_line(long long items_used, const char* name,
    ifstream& file, bool print_verbose, double& total_cost,
    bool& reading_field, string suffix) const
{
  double cost_per_item = 0;
  if (reading_field)
    file >> cost_per_item;
  if (cost_per_item < 0)
    {
      reading_field = false;
      cost_per_item = 0;
    }
  double cost = items_used * cost_per_item;
  total_cost += cost;
  cerr.fill(' ');
  if (items_used)
    {
      cerr << "    ";
      if (print_verbose)
        cerr << setw(10) << cost << " = ";
      cerr << setw(10) << items_used << " " << setw(14)
                      << name;
      if (print_verbose)
        cerr << " @ " << setw(11) << cost_per_item;
      cerr << suffix << endl;
    }
}

bool DataPositions::empty() const
{
  for (auto& x : files)
    for (auto& y : x)
      if (y)
        return false;

  for (auto& x : inputs)
    for (auto& y : x)
      if (y)
        return false;

  for (auto& x : extended)
    if (not x.empty())
      return false;

  if (not edabits.empty())
    return false;

  return true;
}

bool DataPositions::any_more(const DataPositions& other) const
{
  for (unsigned int field_type = 0; field_type < N_DATA_FIELD_TYPE;
      field_type++)
    {
      for (unsigned int dtype = 0; dtype < N_DTYPE; dtype++)
        if (files[field_type][dtype] > other.files[field_type][dtype])
          return true;
      for (unsigned int j = 0; j < min(inputs.size(), other.inputs.size()); j++)
        if (inputs[j][field_type] > other.inputs[j][field_type])
          return true;

      auto& ext = extended[field_type];
      auto& other_ext = other.extended[field_type];
      for (auto it = ext.begin(); it != ext.end(); it++)
        {
          auto x = other_ext.find(it->first);
          if (x == other_ext.end() or it->second > x->second)
            return true;
        }
    }

  for (auto it = edabits.begin(); it != edabits.end(); it++)
    {
      auto x = other.edabits.find(it->first);
      if ((x == other.edabits.end() or it->second > x->second)
          and it->second > 0)
        return true;
    }

  return false;
}

long long DataPositions::total_edabits(int n_bits) const
{
  auto usage = edabits;
  return usage[{false, n_bits}] + usage[{true, n_bits}];
}

long long DataPositions::triples_for_matmul()
{
  long long res = 0;
  for (auto& x : matmuls)
    {
      auto dim = x.first;
      res += x.second * dim[0] * dim[1] * dim[2];
    }
  return res;
}
