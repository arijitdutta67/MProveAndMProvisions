#include "mproveSigs.h"
#include <algorithm>

struct mproveProof {
  rct::keyV addrs;
  rct::keyV cs;
  rct::keyV cprimes;
  std::vector<ringSig> gammas;
  std::vector<lsagSig> sigmas;
  rct::key msg;
  rct::key cassets;
};

class MoneroExchange
{
    size_t m_anonSetSize;
    size_t m_ownkeysSetSize;
    mproveProof m_proof;
    rct::keyV m_ownKeys;
    std::vector<rct::xmr_amount> m_ownAmounts;
    rct::keyV m_amountMasks;
    rct::xmr_amount m_maxAmount = 1000;
    rct::keyV m_cprimeKeys;
  public:
    MoneroExchange(size_t anonSetSize, size_t ownkeysSetSize, rct::key message);
    mproveProof GenerateProofOfAssets();
};

MoneroExchange::MoneroExchange(size_t anonSetSize, size_t ownkeysSetSize, rct::key message)
{
  m_anonSetSize = anonSetSize;
  m_ownkeysSetSize = ownkeysSetSize;
  m_proof.msg = message;
  m_proof.addrs = rct::keyV(anonSetSize);
  m_proof.cs = rct::keyV(anonSetSize);
  m_ownKeys = rct::keyV(anonSetSize);
  m_ownAmounts = std::vector<rct::xmr_amount>(anonSetSize);
  m_amountMasks = rct::keyV(anonSetSize);
  m_cprimeKeys = rct::keyV(anonSetSize);

  for (size_t i = 0; i < anonSetSize; i++)
  {
    if (i < ownkeysSetSize)
    {
      m_ownKeys[i] = rct::skGen();
    }
    else
    {
      sc_0(m_ownKeys[i].bytes);
    }
  }

  // Distribute the known keys randomly in the anonymity set
  std::random_shuffle(m_ownKeys.begin(), m_ownKeys.end());

  for (size_t i = 0; i < anonSetSize; i++)
  {
    if (sc_isnonzero(m_ownKeys[i].bytes) == 0)
    {
      m_proof.addrs[i] = rct::scalarmultBase(m_ownKeys[i]);
      m_ownAmounts[i] = rct::randXmrAmount(m_maxAmount);
      m_amountMasks[i] = rct::skGen();
      m_proof.cs[i] = rct::commit(m_ownAmounts[i], m_amountMasks[i]);
      m_cprimeKeys[i] = rct::skGen();
      m_proof.cprimes[i] = rct::scalarmultBase(m_cprimeKeys[i]);
    }
    else
    {
      m_proof.addrs[i] = rct::pkGen();
      m_proof.cs[i] = rct::pkGen();
      m_ownAmounts[i] = 0;
      m_cprimeKeys[i] = rct::skGen();
      rct::addKeys(m_proof.cprimes[i], rct::scalarmultBase(m_cprimeKeys[i]), m_proof.cs[i]);
    }
  }
}

mproveProof MoneroExchange::GenerateProofOfAssets()
{
  rct::keyV ringPks(2);
  rct::keyV lsagPks(2);
  rct::key csum, cprimesum;

  for (size_t i = 0; i < m_anonSetSize; i++)
  {
    if (sc_isnonzero(m_ownKeys[i].bytes) == 0)
    {
      m_cprimeKeys[i] = rct::skGen();
      m_proof.cprimes[i] = rct::scalarmultBase(m_cprimeKeys[i]);

      // Ring signature generation
      ringPks[0] = m_proof.cprimes[i];
      rct::subKeys(ringPks[1], m_proof.cprimes[i], m_proof.cs[i]);
      m_proof.gammas[i] = RingSig_Gen(m_proof.msg, ringPks, m_cprimeKeys[i], 0);

      // Linkable ring signature generation
      lsagPks[0] = m_proof.addrs[i];
      lsagPks[1] = ringPks[1];
      m_proof.sigmas[i] = LSAG_Gen(m_proof.msg, lsagPks, m_ownKeys[i], 0, hw::get_device("default"));
    }
    else
    {
      m_cprimeKeys[i] = rct::skGen();
      rct::addKeys(m_proof.cprimes[i], rct::scalarmultBase(m_cprimeKeys[i]), m_proof.cs[i]);

      // Ring signature generation
      ringPks[0] = m_proof.cprimes[i];
      rct::subKeys(ringPks[1], m_proof.cprimes[i], m_proof.cs[i]);
      m_proof.gammas[i] = RingSig_Gen(m_proof.msg, ringPks, m_cprimeKeys[i], 1);

      // Linkable ring signature generation
      lsagPks[0] = m_proof.addrs[i];
      lsagPks[1] = ringPks[1];
      m_proof.sigmas[i] = LSAG_Gen(m_proof.msg, lsagPks, m_cprimeKeys[i], 1, hw::get_device("default"));
    }
  }

  csum = rct::addKeys(m_proof.cs);
  cprimesum = rct::addKeys(m_proof.cprimes);
  rct::subKeys(m_proof.cassets, csum, cprimesum);

  return m_proof;
}

bool MProveProofPublicVerification(mproveProof proof)
{
  rct::key csum, cprimesum, cassets;

  csum = rct::addKeys(proof.cs);
  cprimesum = rct::addKeys(proof.cprimes);
  rct::subKeys(cassets, csum, cprimesum);
  if(!rct::equalKeys(cassets, proof.cassets))
  {
    std::cout << "Commitments to assets does not satisfy equation" << std::endl;
    return false;
  }

  rct::keyV ringPks(2);
  rct::keyV lsagPks(2);
  size_t anonSetSize = proof.addrs.size();

  for (size_t i = 0; i < anonSetSize; i++)
  {
      // Ring signature verification
      ringPks[0] = proof.cprimes[i];
      rct::subKeys(ringPks[1], proof.cprimes[i], proof.cs[i]);
      if(!RingSig_Ver(proof.msg, ringPks, proof.gammas[i]))
      {
        std::cout << "Ring signature verification failed at location " << i+1 << std::endl;
        return false;
      }

      // Linkable ring signature verification
      lsagPks[0] = proof.addrs[i];
      lsagPks[1] = ringPks[1];
      if(!LSAG_Ver(proof.msg, lsagPks, proof.sigmas[i]))
      {
        std::cout << "Linkable ring signature verification failed at location " << i+1 << std::endl;
        return false;
      }
  }
  return true;
}
