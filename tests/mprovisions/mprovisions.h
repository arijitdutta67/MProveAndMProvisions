#include "ringct/rctSigs.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "../io.h"
#include <algorithm>


struct mprovisionsProof {
  rct::keyV addrs;
  rct::keyV cs;
  rct::keyV ps;
  rct::keyV Is;
  rct::keyV ms;
  rct::keyV ns;
  rct::keyV responseS;
  rct::keyV responseK;
  rct::keyV responseE;
  rct::keyV responseF;
  rct::keyV responseXhat;
  rct::keyV cZero;
  rct::keyV cOne;
  rct::keyV responseZero;
  rct::keyV responseOne;
};

class MoneroExchange
{
    size_t m_anonSetSize;
    size_t m_ownkeysSetSize;
    mprovisionsProof m_provisions_proof;
    rct::keyV m_ownKeys;
    std::vector<rct::xmr_amount> m_ownAmounts;
    rct::keyV m_amountMasks;
    rct::xmr_amount m_maxAmount = 1000; // Only for generating random amounts per address
    rct::keyV u1;
    rct::keyV u2;
    rct::keyV u3;
    rct::keyV u4;
    rct::keyV u5;
    rct::keyV uZero;
    rct::keyV uOne;
    rct::keyV cF;
    rct::keyV challenge;
    rct::keyV a1;
    rct::keyV a2;
    rct::keyV a3;
    rct::keyV a4;
    rct::keyV a5;
    rct::keyV aZero;
    rct::keyV aOne;
    rct::keyV ks;
    rct::keyV es;
    rct::keyV fs;
    rct::keyV xHats;
    rct::keyV cDiff;
  public:
    MoneroExchange(size_t anonSetSize, size_t ownkeysSetSize);
    mprovisionsProof GenerateMprovisionsPoa();
    mprovisionsProof GetProofMprovisions();
    size_t ProofSizeMprovisions();
    void PrintExchangeState();
};

MoneroExchange::MoneroExchange(size_t anonSetSize, size_t ownkeysSetSize)
{
  m_anonSetSize = anonSetSize;
  m_ownkeysSetSize = ownkeysSetSize;
  m_ownKeys = rct::keyV(anonSetSize);
  m_ownAmounts = std::vector<rct::xmr_amount>(anonSetSize);
  m_amountMasks = rct::keyV(anonSetSize);
  m_provisions_proof.addrs = rct::keyV(anonSetSize);
  m_provisions_proof.cs = rct::keyV(anonSetSize);
  m_provisions_proof.ps = rct::keyV(anonSetSize);
  m_provisions_proof.Is = rct::keyV(anonSetSize);
  m_provisions_proof.ms = rct::keyV(anonSetSize);
  m_provisions_proof.ns = rct::keyV(anonSetSize);
  m_provisions_proof.cZero = rct::keyV(anonSetSize);
  m_provisions_proof.cOne = rct::keyV(anonSetSize);
  m_provisions_proof.responseE = rct::keyV(anonSetSize);
  m_provisions_proof.responseF = rct::keyV(anonSetSize);
  m_provisions_proof.responseK = rct::keyV(anonSetSize);
  m_provisions_proof.responseS = rct::keyV(anonSetSize);
  m_provisions_proof.responseXhat = rct::keyV(anonSetSize);
  m_provisions_proof.responseZero = rct::keyV(anonSetSize);
  m_provisions_proof.responseOne = rct::keyV(anonSetSize);
  u1 = rct::keyV(anonSetSize);
  u2 = rct::keyV(anonSetSize);
  u3 = rct::keyV(anonSetSize);
  u4 = rct::keyV(anonSetSize);
  u5 = rct::keyV(anonSetSize);
  uZero = rct::keyV(anonSetSize);
  uOne = rct::keyV(anonSetSize);
  cF = rct::keyV(anonSetSize);
  challenge = rct::keyV(anonSetSize);
  a1 = rct::keyV(anonSetSize);
  a2 = rct::keyV(anonSetSize);
  a3 = rct::keyV(anonSetSize);
  a4 = rct::keyV(anonSetSize);
  a5 = rct::keyV(anonSetSize);
  aZero = rct::keyV(anonSetSize);
  aOne = rct::keyV(anonSetSize);
  ks = rct::keyV(anonSetSize);
  es = rct::keyV(anonSetSize);
  fs = rct::keyV(anonSetSize);
  xHats = rct::keyV(anonSetSize);
  cDiff = rct::keyV(anonSetSize);
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
    if (sc_isnonzero(m_ownKeys[i].bytes) == 1)
    {
      m_provisions_proof.addrs[i] = rct::scalarmultBase(m_ownKeys[i]);
      m_ownAmounts[i] = rct::randXmrAmount(m_maxAmount);
      m_amountMasks[i] = rct::skGen();
      m_provisions_proof.cs[i] = rct::commit(m_ownAmounts[i], m_amountMasks[i]);
    }
    else
    {
      m_provisions_proof.addrs[i] = rct::pkGen();  
      m_provisions_proof.cs[i] = rct::pkGen();
      m_ownAmounts[i] = 0;
    }
  }
}



mprovisionsProof MoneroExchange::GenerateMprovisionsPoa(){
  // Generation of ps, ms, ns and Is  
  for (size_t i = 0; i < m_anonSetSize; i++)
  {
    if (sc_isnonzero(m_ownKeys[i].bytes) == 1)
    {
        ks[i] = rct::skGen();
        rct::key kG = rct::scalarmultBase(ks[i]);
        rct::addKeys(m_provisions_proof.ps[i], m_provisions_proof.cs[i], kG);
        xHats[i] = m_ownKeys[i];
        rct::key hashPk = rct::hashToPoint(m_provisions_proof.addrs[i]);
        m_provisions_proof.Is[i] = rct::scalarmultKey(hashPk, m_ownKeys[i]);
        es[i] = rct::skGen();
        rct::addKeys(m_provisions_proof.ms[i], m_provisions_proof.Is[i], rct::scalarmultH(es[i]));
        fs[i] = rct::skGen();
        rct::addKeys(m_provisions_proof.ns[i], m_provisions_proof.addrs[i], rct::scalarmultH(fs[i]));
       
    }
    else 
    {
        ks[i] =rct::skGen();
        m_provisions_proof.ps[i] = rct::scalarmultBase(ks[i]);
        sc_0(xHats[i].bytes);
        es[i] = rct::skGen();
        fs[i] = rct::skGen();
        m_provisions_proof.ms[i] = rct::scalarmultH(es[i]);
        m_provisions_proof.ns[i] = rct::scalarmultH(fs[i]);
        rct::key xprime = rct::skGen();
        rct::key hashPk = rct::hashToPoint(m_provisions_proof.addrs[i]);
        m_provisions_proof.Is[i] = rct::scalarmultKey(hashPk, xprime);
    }
  }
    
    for (size_t i = 0; i < m_anonSetSize; i++) 
    {
        // Generation of commitments
        u1[i] = rct::skGen();
        u2[i] = rct::skGen();
        u3[i] = rct::skGen();
        u4[i] = rct::skGen();
        u5[i] = rct::skGen();
        uZero[i] = rct::skGen();
        uOne[i] = rct::skGen();
        cF[i] = rct::skGen(); 
        rct::addKeys(a1[i], rct::scalarmultKey(m_provisions_proof.cs[i],u1[i]), rct::scalarmultBase(u2[i]));
        rct::addKeys(a2[i], rct::scalarmultKey(m_provisions_proof.Is[i], u1[i]), rct::scalarmultH(u3[i]));
        rct::addKeys(a3[i], rct::scalarmultKey(m_provisions_proof.addrs[i], u1[i]), rct::scalarmultH(u4[i]));
        rct::addKeys(a4[i], rct::scalarmultKey(rct::hashToPoint(m_provisions_proof.addrs[i]), u5[i]), rct::scalarmultH(u3[i]));
        rct::addKeys(a5[i], rct::scalarmultBase(u5[i]), rct::scalarmultH(u4[i]));
        if(sc_isnonzero(m_ownKeys[i].bytes) == 1)
        {
            rct::subKeys(aZero[i], rct::scalarmultBase(uZero[i]), rct::scalarmultKey(m_provisions_proof.cs[i], cF[i]));
            aOne[i] = rct::scalarmultBase(uOne[i]);
        }
        else 
        {
            aZero[i] = rct::scalarmultBase(uZero[i]);
            rct::addKeys(aOne[i], rct::scalarmultBase(uOne[i]), rct::scalarmultKey(m_provisions_proof.cs[i],cF[i]));
        }
        // Generation of challenge

        rct::keyV toHash(15);
        toHash[0] = rct::G;
        toHash[1] = rct::H;
        toHash[2] = m_provisions_proof.addrs[i];
        toHash[3] = m_provisions_proof.cs[i];
        toHash[4] = m_provisions_proof.ps[i];
        toHash[5] = m_provisions_proof.Is[i];
        toHash[6] = m_provisions_proof.ms[i];
        toHash[7] = m_provisions_proof.ns[i];
        toHash[8] = a1[i];
        toHash[9] = a2[i];
        toHash[10] = a3[i];
        toHash[11] = a4[i];
        toHash[12] = a5[i];
        toHash[13] = aZero[i];
        toHash[14] = aOne[i];
        challenge[i] = rct::hash_to_scalar(toHash);
        
        // Generation of responses and challenges
        
        rct::key ciKi;
        sc_mul(ciKi.bytes, challenge[i].bytes, ks[i].bytes);  
        sc_add(m_provisions_proof.responseK[i].bytes, u2[i].bytes, ciKi.bytes);     
        rct::key ciEi;
        sc_mul(ciEi.bytes, challenge[i].bytes, es[i].bytes);
        sc_add(m_provisions_proof.responseE[i].bytes, u3[i].bytes, ciEi.bytes);
        rct::key ciFi;
        sc_mul(ciFi.bytes, challenge[i].bytes, fs[i].bytes);
        sc_add(m_provisions_proof.responseF[i].bytes, u4[i].bytes, ciFi.bytes);
        rct::key ciXhatI;
        sc_mul(ciXhatI.bytes, challenge[i].bytes, xHats[i].bytes);
        sc_add(m_provisions_proof.responseXhat[i].bytes, u5[i].bytes, ciXhatI.bytes);
        
        
        if(sc_isnonzero(m_ownKeys[i].bytes) == 1)
        {
           sc_add(m_provisions_proof.responseS[i].bytes, u1[i].bytes, challenge[i].bytes); 
           rct::key cFKi;
           sc_mul(cFKi.bytes, cF[i].bytes, ks[i].bytes);
           sc_add(m_provisions_proof.responseZero[i].bytes, uZero[i].bytes, cFKi.bytes);
           sc_sub(cDiff[i].bytes, challenge[i].bytes, cF[i].bytes);
           rct::key cDiffKi;
           sc_mul(cDiffKi.bytes, cDiff[i].bytes, ks[i].bytes);
           sc_add(m_provisions_proof.responseOne[i].bytes, uOne[i].bytes, cDiffKi.bytes);
           m_provisions_proof.cZero[i] = cF[i];
           m_provisions_proof.cOne[i] = cDiff[i];
        }
        else
        {
            m_provisions_proof.responseS[i] = u1[i];
            sc_sub(cDiff[i].bytes, challenge[i].bytes, cF[i].bytes);
            rct::key cFKi;
            sc_mul(cFKi.bytes, cF[i].bytes, ks[i].bytes);
            rct::key cDiffKi;
            sc_mul(cDiffKi.bytes, cDiff[i].bytes, ks[i].bytes);
            sc_add(m_provisions_proof.responseZero[i].bytes, uZero[i].bytes, cDiffKi.bytes);
            sc_add(m_provisions_proof.responseOne[i].bytes, uOne[i].bytes, cFKi.bytes);
            m_provisions_proof.cZero[i] = cDiff[i];
            m_provisions_proof.cOne[i] = cF[i];
        }
    }    
    
    return m_provisions_proof;

}

bool VerifyMprovisionsPoa(mprovisionsProof mProvisions_proof)
{
    size_t m_anonSetSize = mProvisions_proof.addrs.size();
    for (size_t i = 0; i < m_anonSetSize; i++)
    {
        rct::key transmittedChallenge;
        sc_add(transmittedChallenge.bytes, mProvisions_proof.cOne[i].bytes, mProvisions_proof.cZero[i].bytes);
        rct::key ciPi = rct::scalarmultKey(mProvisions_proof.ps[i], transmittedChallenge);
        rct::key ciMi = rct::scalarmultKey(mProvisions_proof.ms[i], transmittedChallenge);
        rct::key ciNi = rct::scalarmultKey(mProvisions_proof.ns[i], transmittedChallenge);
        rct::key a1_temp, a2_temp, a3_temp, a4_temp, a5_temp;
        rct::addKeys(a1_temp, rct::scalarmultKey(mProvisions_proof.cs[i], mProvisions_proof.responseS[i]), rct::scalarmultBase(mProvisions_proof.responseK[i]));
        rct::addKeys(a2_temp, rct::scalarmultKey(mProvisions_proof.Is[i], mProvisions_proof.responseS[i]), rct::scalarmultH(mProvisions_proof.responseE[i]));
        rct::addKeys(a3_temp, rct::scalarmultKey(mProvisions_proof.addrs[i], mProvisions_proof.responseS[i]), rct::scalarmultH(mProvisions_proof.responseF[i]));
        rct::key hashPk = rct::hashToPoint(mProvisions_proof.addrs[i]);
        rct::addKeys(a4_temp, rct::scalarmultKey(hashPk, mProvisions_proof.responseXhat[i]), rct::scalarmultH(mProvisions_proof.responseE[i]));
        rct::addKeys(a5_temp, rct::scalarmultBase(mProvisions_proof.responseXhat[i]), rct::scalarmultH(mProvisions_proof.responseF[i]));
        rct::key a1Cal, a2Cal, a3Cal, a4Cal, a5Cal;
        rct::subKeys(a1Cal, a1_temp, ciPi);
        rct::subKeys(a2Cal, a2_temp, ciMi);
        rct::subKeys(a3Cal, a3_temp, ciNi);
        rct::subKeys(a4Cal, a4_temp, ciMi);
        rct::subKeys(a5Cal, a5_temp, ciNi);
        rct::key zeroClaim = rct::scalarmultKey(mProvisions_proof.ps[i], mProvisions_proof.cZero[i]);
        rct::key piDiffCi;
        rct::subKeys(piDiffCi, mProvisions_proof.ps[i], mProvisions_proof.cs[i]);
        rct::key oneClaim = rct::scalarmultKey(piDiffCi, mProvisions_proof.cOne[i]);
        rct::key aZeroCal, aOneCal;
        rct::subKeys(aZeroCal, rct::scalarmultBase(mProvisions_proof.responseZero[i]), zeroClaim);
        rct::subKeys(aOneCal, rct::scalarmultBase(mProvisions_proof.responseOne[i]), oneClaim);
        rct::keyV toHash(15);
        toHash[0] = rct::G;
        toHash[1] = rct::H;
        toHash[2] = mProvisions_proof.addrs[i];
        toHash[3] = mProvisions_proof.cs[i];
        toHash[4] = mProvisions_proof.ps[i];
        toHash[5] = mProvisions_proof.Is[i];
        toHash[6] = mProvisions_proof.ms[i];
        toHash[7] = mProvisions_proof.ns[i];
        toHash[8] = a1Cal;
        toHash[9] = a2Cal;
        toHash[10] = a3Cal;
        toHash[11] = a4Cal;
        toHash[12] = a5Cal;
        toHash[13] = aZeroCal;
        toHash[14] = aOneCal;
        rct::key challengeCal = rct::hash_to_scalar(toHash);
        if(!rct::equalKeys(challengeCal, transmittedChallenge))
        {
            std::cout << "Verification failed for i = " << i << std::endl;
            return false;
        }

    }
    // Generation of c_asset
    rct::key c_asset = rct::addKeys(mProvisions_proof.ps);
    return true;
}

size_t MoneroExchange::ProofSizeMprovisions()
{
  size_t psize = 0;
  psize += m_anonSetSize*32; // m_provisions_proof.addrs
  psize += m_anonSetSize*32; // m_provisions_proof.cs
  psize += m_anonSetSize*32; // m_provisions_proof.ps
  psize += m_anonSetSize*32; // m_provisions_proof.Is
  psize += m_anonSetSize*32; // m_provisions_proof.ms
  psize += m_anonSetSize*32; // m_provisions_proof.ns
  psize += m_anonSetSize*32; // m_provisions_proof.responseS
  psize += m_anonSetSize*32; // m_provisions_proof.responseK
  psize += m_anonSetSize*32; // m_provisions_proof.responseE
  psize += m_anonSetSize*32; // m_provisions_proof.responseF
  psize += m_anonSetSize*32; // m_provisions_proof.responseXhat
  psize += m_anonSetSize*32; // m_provisions_proof.cZero
  psize += m_anonSetSize*32; // m_provisions_proof.cOne
  psize += m_anonSetSize*32; // m_provisions_proof.responseZero
  psize += m_anonSetSize*32; // m_provisions_proof.responseOne
  
  return psize;
}



mprovisionsProof MoneroExchange::GetProofMprovisions()
{
    return m_provisions_proof;
}

void MoneroExchange::PrintExchangeState()
{
  std::cout << "Anonymity set size = " << m_anonSetSize << std::endl;
  std::cout << "Own keys set size = " << m_ownkeysSetSize << std::endl;
  std::cout << std::endl;
  size_t index = 1;
  for (size_t i = 0; i < m_anonSetSize; i++)
  {
    if (sc_isnonzero(m_ownKeys[i].bytes) == 1)
    {
      std::cout << "Address at index " << i+1 << " is exchange owned" << std::endl;
      std::cout << "Address is " << index << " out of " << m_ownkeysSetSize << std::endl;
      std::cout << "Address = " << m_provisions_proof.addrs[i] << std::endl;
      std::cout << "Amount in address is " << m_ownAmounts[i] << std::endl;
      std::cout << std::endl;
      index += 1;
    }
  }
}

