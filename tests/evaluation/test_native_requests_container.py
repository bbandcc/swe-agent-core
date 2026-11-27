"""The fixed-material gate keeps both mounts exact and read-only."""
import copy
from pathlib import Path
import unittest

from agent.evaluation.native_requests.tls import IMAGE_LABELS, LABEL, PYTHON
from agent.evaluation.native_requests.container import IMAGE, inspect_expected


class FixedControlMountTests(unittest.TestCase):
    def setUp(self):
        self.inputs = Path.cwd()/'owned-inputs'
        self.lease = {'volume':'swe-fixed-tls-'+'a'*32,'owner':'a'*32}
        self.value = {'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'Privileged':False,
            'PidMode':'','IpcMode':'private','PidsLimit':64,'Memory':536870912,'MemorySwap':536870912,
            'NanoCpus':1000000000,'Tmpfs':{'/tmp':'rw,nosuid,nodev,noexec,size=128m'},
            'LogConfig':{'Type':'none'},'SecurityOpt':['no-new-privileges'],'Devices':[],
            'DeviceRequests':[],'CapDrop':['ALL'],'CapAdd':['NET_ADMIN','SETUID','SETGID','SETPCAP']},
            'Config':{'User':'0:0','Image':IMAGE,'Entrypoint':[PYTHON],'WorkingDir':'/',
                'Cmd':['-I','-S','-B','/trusted/bootstrap.py'],
                'Labels':{**IMAGE_LABELS,LABEL:self.lease['owner']}},
            'Mounts':[{'Type':'bind','Source':str(self.inputs.resolve()),'RW':False,
                'Destination':'/trusted','Propagation':'rprivate'},
                {'Type':'volume','Name':self.lease['volume'],'Driver':'local','RW':False,
                 'Destination':'/fixed-tls'}]}

    def test_exact_two_read_only_mounts_accept_only_the_fixed_lane(self):
        self.assertTrue(inspect_expected(self.value,self.inputs,self.lease))
        self.assertFalse(inspect_expected(self.value,self.inputs))

    def test_wrong_volume_writable_mount_or_extra_mount_is_rejected(self):
        for key,value in [('Name','another-volume'),('RW',True),('Driver','nfs'),('Destination','/elsewhere')]:
            with self.subTest(key=key):
                current=copy.deepcopy(self.value);current['Mounts'][1][key]=value
                self.assertFalse(inspect_expected(current,self.inputs,self.lease))
        current=copy.deepcopy(self.value);current['Mounts'].append(current['Mounts'][0])
        self.assertFalse(inspect_expected(current,self.inputs,self.lease))

    def test_wrong_owner_or_input_source_is_rejected(self):
        current=copy.deepcopy(self.value);current['Config']['Labels'][LABEL]='other'
        self.assertFalse(inspect_expected(current,self.inputs,self.lease))
        current=copy.deepcopy(self.value);current['Mounts'][0]['Source']='other'
        self.assertFalse(inspect_expected(current,self.inputs,self.lease))

    def test_case_entrypoint_or_working_directory_cannot_drift(self):
        for key,value in [('Entrypoint',['/bin/sh']),('WorkingDir','/testbed')]:
            current=copy.deepcopy(self.value);current['Config'][key]=value
            self.assertFalse(inspect_expected(current,self.inputs,self.lease))


if __name__ == '__main__': unittest.main()
