# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2017 Red Hat, Inc.
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details.
# --- END COPYRIGHT BLOCK ---
#
import pytest
from lib389.tasks import *
from lib389.utils import *
from lib389.topologies import topology_m4 as topo_m4
from lib389._constants import *
from . import get_repl_entries

TEST_ENTRY_NAME = 'mmrepl_test'
TEST_ENTRY_DN = 'uid={},{}'.format(TEST_ENTRY_NAME, DEFAULT_SUFFIX)
NEW_SUFFIX_NAME = 'test_repl'
NEW_SUFFIX = 'o={}'.format(NEW_SUFFIX_NAME)
NEW_BACKEND = 'repl_base'

DEBUGGING = os.getenv("DEBUGGING", default=False)
if DEBUGGING:
    logging.getLogger(__name__).setLevel(logging.DEBUG)
else:
    logging.getLogger(__name__).setLevel(logging.INFO)
log = logging.getLogger(__name__)


@pytest.fixture(scope="function")
def test_entry(topo_m4, request):
    """Add test entry to master1"""

    log.info('Adding entry {}'.format(TEST_ENTRY_DN))
    try:
        topo_m4.ms["master1"].add_s(Entry((TEST_ENTRY_DN, {
            'objectclass': 'top person'.split(),
            'objectclass': 'organizationalPerson',
            'objectclass': 'inetorgperson',
            'cn': TEST_ENTRY_NAME,
            'sn': TEST_ENTRY_NAME,
            'uid': TEST_ENTRY_NAME,
            'userpassword': TEST_ENTRY_NAME
        })))
    except ldap.LDAPError as e:
        log.error('Failed to add entry (%s): error (%s)' % (TEST_ENTRY_DN,
                                                            e.message['desc']))
        raise e

    def fin():
        log.info('Deleting entry {}'.format(TEST_ENTRY_DN))
        try:
            topo_m4.ms["master1"].delete_s(TEST_ENTRY_DN)
        except ldap.NO_SUCH_OBJECT:
            log.info("Entry {} wasn't found".format(TEST_ENTRY_DN))

    request.addfinalizer(fin)


@pytest.fixture(scope="function")
def new_suffix(topo_m4, request):
    """Add a new suffix and enable a replication on it"""

    for num in range(1, 5):
        log.info('Adding suffix:{} and backend: {} to master{}'.format(NEW_SUFFIX, NEW_BACKEND, num))
        topo_m4.ms["master{}".format(num)].backend.create(NEW_SUFFIX, {BACKEND_NAME: NEW_BACKEND})
        topo_m4.ms["master{}".format(num)].mappingtree.create(NEW_SUFFIX, NEW_BACKEND)

        try:
            topo_m4.ms["master{}".format(num)].add_s(Entry((NEW_SUFFIX, {
                'objectclass': 'top',
                'objectclass': 'organization',
                'o': NEW_SUFFIX_NAME,
                'description': NEW_SUFFIX_NAME
            })))
        except ldap.LDAPError as e:
            log.error('Failed to add suffix ({}): error ({})'.format(NEW_SUFFIX, e.message['desc']))
            raise

    def fin():
        for num in range(1, 5):
            log.info('Deleting suffix:{} and backend: {} from master{}'.format(NEW_SUFFIX, NEW_BACKEND, num))
            topo_m4.ms["master{}".format(num)].mappingtree.delete(NEW_SUFFIX)
            topo_m4.ms["master{}".format(num)].backend.delete(NEW_SUFFIX)

    request.addfinalizer(fin)


def test_add_entry(topo_m4, test_entry):
    """Check that entries are replicated after add operation

    :id: 024250f1-5f7e-4f3b-a9f5-27741e6fd405
    :setup: Four masters replication setup, an entry
    :steps:
        1. Check entry on all other masters
    :expectedresults:
        1. The entry should be replicated to all masters
    """

    entries = get_repl_entries(topo_m4, TEST_ENTRY_NAME, ["uid"])
    assert all(entries), "Entry {} wasn't replicated successfully".format(TEST_ENTRY_DN)


def test_modify_entry(topo_m4, test_entry):
    """Check that entries are replicated after modify operation

    :id: 36764053-622c-43c2-a132-d7a3ab7d9aaa
    :setup: Four masters replication setup, an entry
    :steps:
        1. Modify the entry on master1 - add attribute
        2. Wait for replication to happen
        3. Check entry on all other masters
        4. Modify the entry on master1 - replace attribute
        5. Wait for replication to happen
        6. Check entry on all other masters
        7. Modify the entry on master1 - delete attribute
        8. Wait for replication to happen
        9. Check entry on all other masters
    :expectedresults:
        1. Attribute should be successfully added
        2. Some time should pass
        3. The change should be present on all masters
        4. Attribute should be successfully replaced
        5. Some time should pass
        6. The change should be present on all masters
        4. Attribute should be successfully deleted
        8. Some time should pass
        9. The change should be present on all masters
    """

    log.info('Modifying entry {} - add operation'.format(TEST_ENTRY_DN))
    try:
        topo_m4.ms["master1"].modify_s(TEST_ENTRY_DN, [(ldap.MOD_ADD,
                                                        'mail', '{}@redhat.com'.format(TEST_ENTRY_NAME))])
    except ldap.LDAPError as e:
        log.error('Failed to modify entry (%s): error (%s)' % (TEST_ENTRY_DN,
                                                               e.message['desc']))
        raise e
    time.sleep(1)

    entries = get_repl_entries(topo_m4, TEST_ENTRY_NAME, ["mail"])
    assert all(entry["mail"] == "{}@redhat.com".format(TEST_ENTRY_NAME)
               for entry in entries), "Entry attr {} wasn't replicated successfully".format(TEST_ENTRY_DN)

    log.info('Modifying entry {} - replace operation'.format(TEST_ENTRY_DN))
    try:
        topo_m4.ms["master1"].modify_s(TEST_ENTRY_DN, [(ldap.MOD_REPLACE,
                                                        'mail', '{}@greenhat.com'.format(TEST_ENTRY_NAME))])
    except ldap.LDAPError as e:
        log.error('Failed to modify entry (%s): error (%s)' % (TEST_ENTRY_DN,
                                                               e.message['desc']))
        raise e
    time.sleep(1)

    entries = get_repl_entries(topo_m4, TEST_ENTRY_NAME, ["mail"])
    assert all(entry["mail"] == "{}@greenhat.com".format(TEST_ENTRY_NAME)
               for entry in entries), "Entry attr {} wasn't replicated successfully".format(TEST_ENTRY_DN)

    log.info('Modifying entry {} - delete operation'.format(TEST_ENTRY_DN))
    try:
        topo_m4.ms["master1"].modify_s(TEST_ENTRY_DN, [(ldap.MOD_DELETE,
                                                        'mail', '{}@greenhat.com'.format(TEST_ENTRY_NAME))])
    except ldap.LDAPError as e:
        log.error('Failed to modify entry (%s): error (%s)' % (TEST_ENTRY_DN,
                                                               e.message['desc']))
        raise e
    time.sleep(1)

    entries = get_repl_entries(topo_m4, TEST_ENTRY_NAME, ["mail"])
    assert all(not entry["mail"] for entry in entries), "Entry attr {} wasn't replicated successfully".format(
        TEST_ENTRY_DN)


def test_delete_entry(topo_m4, test_entry):
    """Check that entry deletion is replicated after delete operation

    :id: 18437262-9d6a-4b98-a47a-6182501ab9bc
    :setup: Four masters replication setup, an entry
    :steps:
        1. Delete the entry from master1
        2. Check entry on all other masters
    :expectedresults:
        1. The entry should be deleted
        2. The change should be present on all masters
    """

    log.info('Deleting entry {} during the test'.format(TEST_ENTRY_DN))
    topo_m4.ms["master1"].delete_s(TEST_ENTRY_DN)

    entries = get_repl_entries(topo_m4, TEST_ENTRY_NAME, ["uid"])
    assert not entries, "Entry deletion {} wasn't replicated successfully".format(TEST_ENTRY_DN)


@pytest.mark.parametrize("delold", [0, 1])
def test_modrdn_entry(topo_m4, test_entry, delold):
    """Check that entries are replicated after modrdn operation

    :id: 02558e6d-a745-45ae-8d88-34fe9b16adc9
    :setup: Four masters replication setup, an entry
    :steps:
        1. Make modrdn operation on entry on master1 with both delold 1 and 0
        2. Check entry on all other masters
    :expectedresults:
        1. Modrdn operation should be successful
        2. The change should be present on all masters
    """

    newrdn_name = 'newrdn'
    newrdn_dn = 'uid={},{}'.format(newrdn_name, DEFAULT_SUFFIX)
    log.info('Modify entry RDN {}'.format(TEST_ENTRY_DN))
    try:
        topo_m4.ms["master1"].modrdn_s(TEST_ENTRY_DN, 'uid={}'.format(newrdn_name), delold)
    except ldap.LDAPError as e:
        log.error('Failed to modrdn entry (%s): error (%s)' % (TEST_ENTRY_DN,
                                                               e.message['desc']))
        raise e

    try:
        entries_new = get_repl_entries(topo_m4, newrdn_name, ["uid"])
        assert all(entries_new), "Entry {} wasn't replicated successfully".format(newrdn_name)
        if delold == 0:
            entries_old = get_repl_entries(topo_m4, TEST_ENTRY_NAME, ["uid"])
            assert all(entries_old), "Entry with old rdn {} wasn't replicated successfully".format(TEST_ENTRY_DN)
        else:
            entries_old = get_repl_entries(topo_m4, TEST_ENTRY_NAME, ["uid"])
            assert not entries_old, "Entry with old rdn {} wasn't removed in replicas successfully".format(
                TEST_ENTRY_DN)
    finally:
        log.info('Remove entry with new RDN {}'.format(newrdn_dn))
        topo_m4.ms["master1"].delete_s(newrdn_dn)


def test_modrdn_after_pause(topo_m4):
    """Check that changes are properly replicated after replica pause

    :id: 6271dc9c-a993-4a9e-9c6d-05650cdab282
    :setup: Four masters replication setup, an entry
    :steps:
        1. Pause all replicas
        2. Make modrdn operation on entry on master1
        3. Resume all replicas
        4. Wait for replication to happen
        5. Check entry on all other masters
    :expectedresults:
        1. Replicas should be paused
        2. Modrdn operation should be successful
        3. Replicas should be resumed
        4. Some time should pass
        5. The change should be present on all masters
    """

    newrdn_name = 'newrdn'
    newrdn_dn = 'uid={},{}'.format(newrdn_name, DEFAULT_SUFFIX)

    log.info('Adding entry {}'.format(TEST_ENTRY_DN))
    try:
        topo_m4.ms["master1"].add_s(Entry((TEST_ENTRY_DN, {
            'objectclass': 'top person'.split(),
            'objectclass': 'organizationalPerson',
            'objectclass': 'inetorgperson',
            'cn': TEST_ENTRY_NAME,
            'sn': TEST_ENTRY_NAME,
            'uid': TEST_ENTRY_NAME
        })))
    except ldap.LDAPError as e:
        log.error('Failed to add entry (%s): error (%s)' % (TEST_ENTRY_DN,
                                                            e.message['desc']))
        raise e

    log.info('Pause all replicas')
    topo_m4.pause_all_replicas()

    log.info('Modify entry RDN {}'.format(TEST_ENTRY_DN))
    try:
        topo_m4.ms["master1"].modrdn_s(TEST_ENTRY_DN, 'uid={}'.format(newrdn_name))
    except ldap.LDAPError as e:
        log.error('Failed to modrdn entry (%s): error (%s)' % (TEST_ENTRY_DN,
                                                               e.message['desc']))
        raise e

    log.info('Resume all replicas')
    topo_m4.resume_all_replicas()

    log.info('Wait for replication to happen')
    time.sleep(3)

    try:
        entries_new = get_repl_entries(topo_m4, newrdn_name, ["uid"])
        assert all(entries_new), "Entry {} wasn't replicated successfully".format(newrdn_name)
    finally:
        log.info('Remove entry with new RDN {}'.format(newrdn_dn))
        topo_m4.ms["master1"].delete_s(newrdn_dn)


@pytest.mark.bz842441
def test_modify_stripattrs(topo_m4):
    """Check that we can modify nsds5replicastripattrs

    :id: f36abed8-e262-4f35-98aa-71ae55611aaa
    :setup: Four masters replication setup
    :steps:
        1. Modify nsds5replicastripattrs attribute on any agreement
        2. Search for the modified attribute
    :expectedresults: It should be contain the value
        1. nsds5replicastripattrs should be successfully set
        2. The modified attribute should be the one we set
    """

    m1 = topo_m4.ms["master1"]
    agreement = m1.agreement.list(suffix=DEFAULT_SUFFIX)[0].dn
    attr_value = 'modifiersname modifytimestamp'

    log.info('Modify nsds5replicastripattrs with {}'.format(attr_value))
    m1.modify_s(agreement, [(ldap.MOD_REPLACE, 'nsds5replicastripattrs', attr_value)])

    log.info('Check nsds5replicastripattrs for {}'.format(attr_value))
    entries = m1.search_s(agreement, ldap.SCOPE_BASE, "objectclass=*", ['nsds5replicastripattrs'])
    assert attr_value in entries[0].data['nsds5replicastripattrs']


def test_new_suffix(topo_m4, new_suffix):
    """Check that we can enable replication on a new suffix

    :id: d44a9ed4-26b0-4189-b0d0-b2b336ddccbd
    :setup: Four masters replication setup, a new suffix
    :steps:
        1. Enable replication on the new suffix
        2. Check if replication works
        3. Disable replication on the new suffix
    :expectedresults:
        1. Replication on the new suffix should be enabled
        2. Replication should work
        3. Replication on the new suffix should be disabled
    """

    m1 = topo_m4.ms["master1"]
    m2 = topo_m4.ms["master2"]
    log.info('Enable replication for new suffix {} on two masters'.format(NEW_SUFFIX))
    m1.replica.enableReplication(NEW_SUFFIX, ReplicaRole.MASTER, 101)
    m2.replica.enableReplication(NEW_SUFFIX, ReplicaRole.MASTER, 102)

    log.info("Creating agreement from master1 to master2")
    properties = {RA_NAME: 'newMeTo_{}:{}'.format(m2.host, str(m2.port)),
                  RA_BINDDN: defaultProperties[REPLICATION_BIND_DN],
                  RA_BINDPW: defaultProperties[REPLICATION_BIND_PW],
                  RA_METHOD: defaultProperties[REPLICATION_BIND_METHOD],
                  RA_TRANSPORT_PROT: defaultProperties[REPLICATION_TRANSPORT]}
    m1_m2_agmt = m1.agreement.create(NEW_SUFFIX, m2.host, m2.port, properties)

    if not m1_m2_agmt:
        log.fatal("Fail to create a hub -> consumer replica agreement")
        sys.exit(1)
    log.info("{} is created".format(m1_m2_agmt))

    # Allow the replicas to get situated with the new agreements...
    time.sleep(2)

    log.info("Initialize the agreement")
    m1.agreement.init(NEW_SUFFIX, m2.host, m2.port)
    m1.waitForReplInit(m1_m2_agmt)

    log.info("Check the replication is working")
    assert m1.testReplication(NEW_SUFFIX, m2), 'Replication for new suffix {} is not working.'.format(NEW_SUFFIX)

    log.info("Delete the agreement")
    m1.agreement.delete(NEW_SUFFIX, m2.host, m2.port, m1_m2_agmt)

    log.info("Disable replication for the new suffix")
    m1.replica.disableReplication(NEW_SUFFIX)
    m2.replica.disableReplication(NEW_SUFFIX)


def test_many_attrs(topo_m4, test_entry):
    """Check a replication with many attributes (add and delete)

    :id: d540b358-f67a-43c6-8df5-7c74b3cb7523
    :setup: Four masters replication setup, a test entry
    :steps:
        1. Add 10 new attributes to the entry
        2. Delete few attributes: one from the beginning,
           two from the middle and one from the end
        3. Check that the changes were replicated in the right order
    :expectedresults:
        1. The attributes should be successfully added
        2. Delete operations should be successful
        3. The changes should be replicated in the right order
    """

    m1 = topo_m4.ms["master1"]
    add_list = map(lambda x: "test{}".format(x), range(10))
    delete_list = map(lambda x: "test{}".format(x), [0, 4, 7, 9])

    log.info('Modifying entry {} - 10 add operations'.format(TEST_ENTRY_DN))
    for add_name in add_list:
        try:
            m1.modify_s(TEST_ENTRY_DN, [(ldap.MOD_ADD, 'description', add_name)])
        except ldap.LDAPError as e:
            log.error('Failed to modify entry (%s): error (%s)' % (TEST_ENTRY_DN, e.message['desc']))
            raise e

    log.info('Check that everything was properly replicated after an add operation')
    entries = get_repl_entries(topo_m4, TEST_ENTRY_NAME, ["description"])
    for entry in entries:
        assert all(entry.getValues("description")[i] == add_name for i, add_name in enumerate(add_list))

    log.info('Modifying entry {} - 4 delete operations for {}'.format(TEST_ENTRY_DN, str(delete_list)))
    for delete_name in delete_list:
        try:
            m1.modify_s(TEST_ENTRY_DN, [(ldap.MOD_DELETE, 'description', delete_name)])
        except ldap.LDAPError as e:
            log.error('Failed to modify entry (%s): error (%s)' % (TEST_ENTRY_DN, e.message['desc']))
            raise e

    log.info('Check that everything was properly replicated after a delete operation')
    entries = get_repl_entries(topo_m4, TEST_ENTRY_NAME, ["description"])
    for entry in entries:
        for i, value in enumerate(entry.getValues("description")):
            assert value == [name for name in add_list if name not in delete_list][i]
            assert value not in delete_list


if __name__ == '__main__':
    # Run isolated
    # -s for DEBUG mode
    CURRENT_FILE = os.path.realpath(__file__)
    pytest.main("-s %s" % CURRENT_FILE)
