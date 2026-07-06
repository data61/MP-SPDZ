/*
 * DataSetup.h
 *
 */

#ifndef FHEOFFLINE_DATASETUP_H_
#define FHEOFFLINE_DATASETUP_H_

#include "Networking/Player.h"
#include "FHE/FHE_Keys.h"
#include "FHE/FHE_Params.h"
#include "FHE/P2Data.h"
#include "Math/Setup.h"

class DataSetup;
class MachineBase;
class MultiplicativeMachine;

template <class FD>
class PartSetup
{
public:
  typedef typename FD::T T;

  FHE_Params params;
  FD FieldD;
  FHE_PK pk;
  FHE_SK sk;
  Ciphertext calpha;
  typename FD::T alphai;

  static string name()
  {
    return "GlobalParams-" + T::type_string();
  }

  static string protocol_name(bool covert)
  {
    if (covert)
      return "ChaiGear";
    else
      return "HighGear";
  }

  PartSetup();
  void generate_setup(int n_parties, int plaintext_length, int sec, int slack,
      bool round_up);

  void fake(vector<FHE_SK>& sks, vector<T>& alphais, int nplayers,
      bool distributed = true, bool check_security = true);
  void fake(vector<PartSetup<FD> >& setups, int nplayers,
      bool distributed = true, bool check_security = true);
  void insecure_debug_keys(vector<PartSetup<FD> >& setups, int nplayers, bool simple_pk);

  void pack(octetStream& os);
  void unpack(octetStream& os);

  void init_field();

  void check() const;
  bool operator!=(const PartSetup<FD>& other);

  void secure_init(Player& P, MachineBase& machine, int plaintext_length,
      int sec, bool read_only = false);
  void generate(Player& P, MachineBase& machine, int plaintext_length,
      int sec);
  void check(Player& P, MachineBase& machine);

  void covert_key_generation(Player& P, MachineBase&, int num_runs);
  void covert_mac_generation(Player& P, MachineBase&, int num_runs);

  void key_and_mac_generation(Player& P, MachineBase& machine, int num_runs,
      false_type);
  void key_and_mac_generation(Player& P, MachineBase& machine, int num_runs,
      true_type);

  void output(Names& N);
};

class DataSetup
{
public:
  PartSetup<FFT_Data> setup_p;
  PartSetup<P2Data> setup_2;

  DataSetup();
  DataSetup(const DataSetup& other) : DataSetup() { *this = other; }
  DataSetup& operator=(const DataSetup& other);

  template <class FD>
  PartSetup<FD>& part();

  template <class FD>
  PartSetup<FD>& get_setup() { return part<FD>(); }
};

template<> inline PartSetup<FFT_Data>& DataSetup::part<FFT_Data>() { return setup_p; }
template<> inline PartSetup<P2Data>& DataSetup::part<P2Data>() { return setup_2; }

#endif /* FHEOFFLINE_DATASETUP_H_ */
