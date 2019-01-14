#include "mprovisions.h"
#include <cstdlib>

using namespace std;

int main(int argc, char *argv[]) {
  if (argc < 4)
  {
    cout << "Usage: mprovisions-tests anonSetSize ownKeysSetSize print" << endl;
    cout << "print should be 0 or 1" << endl;
    return 1;
  }
  int anonSetSize, ownKeysSetSize, print;
  anonSetSize = atoi(argv[1]);
  ownKeysSetSize = atoi(argv[2]);
  print = atoi(argv[3]);

  MoneroExchange exch(anonSetSize, ownKeysSetSize);
  mprovisionsProof p = exch.GenerateMprovisionsPoa();
  VerifyMprovisionsPoa(p);
  cout << "Proof size for MProvisions = " << exch.ProofSizeMprovisions() << endl;
  if(print)
  {
    exch.PrintExchangeState();
  }
  return 0;
}
