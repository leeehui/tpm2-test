#!/bin/bash
#;**********************************************************************;
#
# Copyright (c) 2018, Intel Corporation
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3. Neither the name of Intel Corporation nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
# THE POSSIBILITY OF SUCH DAMAGE.
#;**********************************************************************;
export TPM2_ABRMD="tpm2-abrmd" TPM2_SIM="tpm_server" PATH="/home/tss/bin:/home/tss/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin" TPM2_SIM_NV_CHIP="" TPM2_TOOLS_TEST_FIXTURES=""

source helpers.sh

cleanup() {
  rm -f

  ina "$@" "keep-context"
  if [ $? -ne 0 ]; then
    rm -f context.out
  fi

  rm -f key.ctx out.yaml

  ina "$@" "no-shut-down"
  if [ $? -ne 0 ]; then
    shut_down
  fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

echo "start."
TPM_CC_Duplicate=0x14B

echo "creating ek"
tpm2_createprimary -Q -a e -g sha256 -G rsa -o ek.ctx

echo "creating aik"
tpm2_create -Q -g sha256 -G rsa -u ak.pub -r ak.priv  -C ek.ctx

echo "creating src storage key"
tpm2_createprimary -Q -a o -g sha256 -G rsa -o src.ctx

echo "creating dst storage key"
tpm2_createprimary -Q -a o -g sha256 -G rsa -o dst.ctx

echo "creating policy for keyedhash key which contains kwk"

echo "  start authsession for trial policy session p1.session, Do NOT use '-a' which is used in real authorization"
tpm2_startauthsession -Q -g sha256 -S p1.session

echo "  bind trial policy to TPM_CC_Duplicate, now tpm2_policyget digest is not available, acctualy we just need to get policy digest"
tpm2_policycommandcode -Q -S p1.session -o p1.data $TPM_CC_Duplicate

echo "  load ak"
tpm2_load -Q -C ek.ctx -u ak.pub -r ak.priv -n ak.name -o ak.ctx

echo "  sign the trial policy p1"
tpm2_sign -Q  -c ak.ctx -G sha256 -m p1.data -s p1.sig

echo "  verify the trial policy signature"
tpm2_verifysignature -Q -c ak.ctx -G sha256 -m p1.data -s p1.sig -t p1.tk

echo "  bind policy to ak"
tpm2_policyauthorize -Q -S p1.session -f p1.data -o p1.data.auth -n ak.name -t p1.tk

echo "  flush ak and policy session"
tpm2_flushcontext -Q -c ak.ctx -S p1.session

echo "12345678" > kwk.data

echo "create keyedhash key containing fake kwk"
tpm2_create -Q -C src.ctx -L p1.data.auth -g sha256 -u dupkey.pub -r dupkey.priv -A userwithauth -I kwk.data

echo "duplicate keyedhash key"

echo "  load keyedhash key"
tpm2_load -Q -C src.ctx -u dupkey.pub -r dupkey.priv -n dupkey.name -o dupkey.ctx

echo "  start authsession p1.session"
tpm2_startauthsession -Q -g sha256 -S p2.session

echo "  read dst key name"
tpm2_readpublic -Q -c dst.ctx -n dst.name
#dst_name=`yaml_get_kv dst.log \"name\"`
#echo "  $dst_name"

echo "  select duplicate destination"
tpm2_policyduplicationselect -Q -i -S p2.session -n dupkey.name -p dst.name

#Note: policyduplicationselect do NOT allow any command code exists in policy sessioin
#      so tpm2_policycommandcode locates after the tpm2_policyduplicationselect
echo "  bind trial policy to TPM_CC_Duplicate"
tpm2_policycommandcode -Q -S p2.session -o p2.data $TPM_CC_Duplicate

echo "  flush authsession p2.session"
tpm2_flushcontext -Q -c dupkey.ctx -S p2.session

rm ak.name ak.ctx
echo "  load ak"
tpm2_load -Q -C ek.ctx -u ak.pub -r ak.priv -n ak.name -o ak.ctx

echo "  sign the trial policy p2"
tpm2_sign -Q  -c ak.ctx -G sha256 -m p2.data -s p2.sig

echo "  verify the trial policy signature"
tpm2_verifysignature -Q -c ak.ctx -G sha256 -m p2.data -s p2.sig -t p2.tk

echo "  flush ak"
tpm2_flushcontext -Q -c ak.ctx

echo "  start real authsession p3.session"
tpm2_startauthsession -Q -a -g sha256 -S p3.session

echo "  select duplicate destination"
tpm2_policyduplicationselect -Q -i -S p3.session -n dupkey.name -p dst.name

echo "  bind trial policy to TPM_CC_Duplicate"
tpm2_policycommandcode -Q -S p3.session -o p3.data $TPM_CC_Duplicate

echo "  bind policy to ak"
tpm2_policyauthorize -Q -S p3.session -f p3.data -o p3.data.auth -n ak.name -t p2.tk

echo "end."
