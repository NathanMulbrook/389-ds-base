# --- BEGIN COPYRIGHT BLOCK ---
# Copyright (C) 2015 Red Hat, Inc.
# All rights reserved.
#
# License: GPL (version 3 or any later version).
# See LICENSE for details.
# --- END COPYRIGHT BLOCK ---

import time
import os.path
import ldap
from datetime import datetime


from lib389 import Entry
from lib389._mapped_object import DSLdapObject
from lib389.exceptions import Error
from lib389._constants import (
        DEFAULT_SUFFIX, DEFAULT_BENAME, DN_EXPORT_TASK, DN_BACKUP_TASK,
        DN_IMPORT_TASK, DN_RESTORE_TASK, DN_INDEX_TASK, DN_MBO_TASK,
        DN_TOMB_FIXUP_TASK, DN_TASKS, DIRSRV_STATE_ONLINE
        )
from lib389.properties import (
        TASK_WAIT, EXPORT_REPL_INFO, MT_PROPNAME_TO_ATTRNAME, MT_SUFFIX,
        TASK_TOMB_STRIP
        )


class Task(DSLdapObject):
    def __init__(self, instance, dn=None):
        super(Task, self).__init__(instance, dn)
        self._rdn_attribute = 'cn'
        self._must_attributes = ['cn']
        self._create_objectclasses = ['top', 'extensibleObject']
        self._protected = False
        self._exit_code = None

    def is_complete(self):
        """Return True if task is complete, else False."""
        self._exit_code = self.get_attr_val("nsTaskExitCode")
        if not self.exists() or self._exit_code is not None:
            return True
        return False

    def get_exit_code(self):
        """Return task's exit code if task is complete, else None."""
        if self.is_complete():
            try:
                return int(self._exit_code)
            except TypeError:
                return None
        return None

    def wait(self, timeout=120):
        """Wait until task is complete."""
        count = 0
        while count < timeout:
            if self.is_complete():
                break
            count = count + 1
            time.sleep(2)

    def create(self, rdn=None, properties={}, basedn=None):
        properties['cn'] = self.cn
        return super(Task, self).create(rdn, properties, basedn)

    @staticmethod
    def _get_task_date():
        """Return a timestamp to use in naming new task entries."""
        return datetime.now().isoformat()


class MemberOfFixupTask(Task):
    def __init__(self, instance, dn=None):
        self.cn = 'memberOf_fixup_' + Task._get_task_date()
        dn = "cn=" + self.cn + "," + DN_MBO_TASK

        super(MemberOfFixupTask, self).__init__(instance, dn)
        self._must_attributes.extend(['basedn'])


class USNTombstoneCleanupTask(Task):
    def __init__(self, instance, dn=None):
        self.cn = 'usn_cleanup_' + Task._get_task_date()
        dn = "cn=" + self.cn + ",cn=USN tombstone cleanup task," + DN_TASKS

        super(USNTombstoneCleanupTask, self).__init__(instance, dn)

    def _validate(self, rdn, properties, basedn):
        if not 'suffix' in properties and not 'backend' in properties:
            raise Error("Either suffix or backend must be specified for cleanup task.")

        return super(USNTombstoneCleanupTask, self)._validate(rdn, properties, basedn)

class SchemaReloadTask(Task):
    def __init__(self, instance, dn=None):
        self.cn = 'schema_reload_' + Task._get_task_date()
        dn = "cn=" + self.cn + ",cn=schema reload task," + DN_TASKS

        super(SchemaReloadTask, self).__init__(instance, dn)

class AbortCleanAllRUVTask(Task):
    """Abort the Clean All Ruv task on all masters. You should
    call this from "CleanAllRUVTask.abort()" instead to provide
    proper linking of the task information.

    :param instance: The instance
    :type instance: lib389.DirSrv
    """
    def __init__(self, instance, dn=None):
        self.cn = 'abortcleanallruv_' + Task._get_task_date()
        dn = "cn=" + self.cn + ",cn=abort cleanallruv," + DN_TASKS

        super(AbortCleanAllRUVTask, self).__init__(instance, dn)

class CleanAllRUVTask(Task):
    """Create the clean all ruv task. This will be replicated through
    a topology to remove non-present ruvs. Note that if a ruv is NOT
    able to be removed, this indicates a dangling replication agreement
    on *some* master in the topology.

    :param instance: The instance
    :type instance: lib389.DirSrv
    """
    def __init__(self, instance, dn=None):
        self.cn = 'cleanallruv_' + Task._get_task_date()
        dn = "cn=" + self.cn + ",cn=cleanallruv," + DN_TASKS
        self._properties = None

        super(CleanAllRUVTask, self).__init__(instance, dn)

    def create(self, rdn=None, properties=None, basedn=None):
        """Create the cleanallruvtask.

        :param rdn: RDN of the new entry.
        :type rdn: str
        :param properties: Attributes for the new entry
        :type properties: dict
        :param basedn: Basedn to create the entry. Do not change this.
        :type basedn: str
        """
        # Stash the props for abort
        self._properties = properties
        return super(CleanAllRUVTask, self).create(rdn, properties, basedn)

    def abort(self, certify=False):
        """Abort the current cleanallruvtask.

        :param certify: certify abort on all masters
        :type certify: bool
        :returns: AbortCleanAllRUVTask
        """
        if certify is True:
            self._properties['replica-certify-all'] = 'yes'
        else:
            self._properties['replica-certify-all'] = 'no'
        # Then create the abort.
        abort_task = AbortCleanAllRUVTask(self._instance)
        abort_task.create(properties=self._properties)
        return abort_task

class Tasks(object):
    proxied_methods = 'search_s getEntry'.split()

    def __init__(self, conn):
        """@param conn - a DirSrv instance"""
        self.conn = conn
        self.log = conn.log
        self.dn = None  # DN of the last task attempted
        self.entry = None

    def __getattr__(self, name):
        from lib389 import DirSrv
        if name in Tasks.proxied_methods:
            return DirSrv.__getattr__(self.conn, name)

    def checkTask(self, entry, dowait=False):
        '''check task status - task is complete when the nsTaskExitCode attr
        is set return a 2 tuple (true/false,code) first is false if task is
        running, true if done - if true, second is the exit code - if dowait
        is True, this function will block until the task is complete'''
        attrlist = ['nsTaskLog', 'nsTaskStatus', 'nsTaskExitCode',
                    'nsTaskCurrentItem', 'nsTaskTotalItems']
        done = False
        exitCode = 0
        dn = entry.dn
        while not done:
            entry = self.conn.getEntry(dn, attrlist=attrlist)
            self.log.debug("task entry %r" % entry)

            if entry.nsTaskExitCode:
                exitCode = int(entry.nsTaskExitCode)
                done = True
            if dowait:
                time.sleep(1)
            else:
                break
        return (done, exitCode)

    def importLDIF(self, suffix=None, benamebase=None, input_file=None,
                   args=None):
        '''
        Import from a LDIF format a given 'suffix' (or 'benamebase' that stores
        that suffix).  It uses an internal task to acheive this request.

        If 'suffix' and 'benamebase' are specified, it uses 'benamebase' first
        else 'suffix'.
        If both 'suffix' and 'benamebase' are missing it raise ValueError

        'input_file' is the ldif input file

        @param suffix - suffix of the backend
        @param benamebase - 'commonname'/'cn' of the backend (e.g. 'userRoot')
        @param ldif_input - file that will contain the entries in LDIF format
                            to import
        @param args - is a dictionary that contains modifier of the import task
                wait: True/[False] - If True, 'export' waits for the completion
                                     of the task before to return

        @return None

        @raise ValueError

        '''
        if self.conn.state != DIRSRV_STATE_ONLINE:
            raise ValueError("Invalid Server State %s! Must be online" % self.conn.state)

        # Checking the parameters
        if not benamebase and not suffix:
            raise ValueError("Specify either bename or suffix")

        if not input_file:
            raise ValueError("input_file is mandatory")

        if not os.path.exists(input_file):
            raise ValueError("Import file (%s) does not exist" % input_file)

        # Prepare the task entry
        cn = "import_" + time.strftime("%m%d%Y_%H%M%S", time.localtime())
        dn = "cn=%s,%s" % (cn, DN_IMPORT_TASK)
        entry = Entry(dn)
        entry.setValues('objectclass', 'top', 'extensibleObject')
        entry.setValues('cn', cn)
        entry.setValues('nsFilename', input_file)
        if benamebase:
            entry.setValues('nsInstance', benamebase)
        else:
            entry.setValues('nsIncludeSuffix', suffix)

        # start the task and possibly wait for task completion
        self.conn.add_s(entry)

        exitCode = 0
        if args and args.get(TASK_WAIT, False):
            (done, exitCode) = self.conn.tasks.checkTask(entry, True)

        if exitCode:
            self.log.error("Error: import task %s for file %s exited with %d" %
                           (cn, input_file, exitCode))
        else:
            self.log.info("Import task %s for file %s completed successfully" %
                          (cn, input_file))
        self.dn = dn
        self.entry = entry
        return exitCode

    def exportLDIF(self, suffix=None, benamebase=None, output_file=None,
                   args=None):
        '''
        Export in a LDIF format a given 'suffix' (or 'benamebase' that stores
        that suffix).  It uses an internal task to acheive this request.

        If 'suffix' and 'benamebase' are specified, it uses 'benamebase' first
        else 'suffix'.
        If both 'suffix' and 'benamebase' are missing it raises ValueError

        'output_file' is the output file of the export

        @param suffix - suffix of the backend
        @param benamebase - 'commonname'/'cn' of the backend (e.g. 'userRoot')
        @param output_file - file that will contain the exported suffix in LDIF
                             format
        @param args - is a dictionary that contains modifier of the export task
                wait: True/[False] - If True, 'export' waits for the completion
                                     of the task before to return
                repl-info: True/[False] - If True, it adds the replication meta
                                          data (state information, tombstones
                                          and RUV) in the exported file

        @return None

        @raise ValueError

        '''

        # Checking the parameters
        if not benamebase and not suffix:
            raise ValueError("Specify either bename or suffix")

        if not output_file:
            raise ValueError("output_file is mandatory")

        # Prepare the task entry
        cn = "export_" + time.strftime("%m%d%Y_%H%M%S", time.localtime())
        dn = "cn=%s,%s" % (cn, DN_EXPORT_TASK)
        entry = Entry(dn)
        entry.update({
            'objectclass': ['top', 'extensibleObject'],
            'cn': cn,
            'nsFilename': output_file
        })
        if benamebase:
            entry.setValues('nsInstance', benamebase)
        else:
            entry.setValues('nsIncludeSuffix', suffix)

        if args.get(EXPORT_REPL_INFO, False):
            entry.setValues('nsExportReplica', 'true')

        # start the task and possibly wait for task completion
        self.conn.add_s(entry)
        exitCode = 0
        if args and args.get(TASK_WAIT, False):
            (done, exitCode) = self.conn.tasks.checkTask(entry, True)

        if exitCode:
            self.log.error("Error: export task %s for file %s exited with %d" %
                           (cn, output_file, exitCode))
        else:
            self.log.info("Export task %s for file %s completed successfully" %
                          (cn, output_file))

        self.dn = dn
        self.entry = entry

        return exitCode

    def db2bak(self, backup_dir=None, args=None):
        '''
        Perform a backup by creating a db2bak task

        @param backup_dir - backup directory
        @param args - is a dictionary that contains modifier of the task
                wait: True/[False] - If True,  waits for the completion of the
                                     task before to return

        @return exit code

        @raise ValueError: if bename name does not exist
        '''

        # Checking the parameters
        if not backup_dir:
            raise ValueError("You must specify a backup directory.")

        # build the task entry
        cn = "backup_" + time.strftime("%m%d%Y_%H%M%S", time.localtime())
        dn = "cn=%s,%s" % (cn, DN_BACKUP_TASK)
        entry = Entry(dn)
        entry.update({
            'objectclass': ['top', 'extensibleObject'],
            'cn': cn,
            'nsArchiveDir': backup_dir,
            'nsDatabaseType': 'ldbm database'
        })

        # start the task and possibly wait for task completion
        try:
            self.conn.add_s(entry)
        except ldap.ALREADY_EXISTS:
            self.log.error("Fail to add the backup task (%s)" % dn)
            return -1

        exitCode = 0
        if args and args.get(TASK_WAIT, False):
            (done, exitCode) = self.conn.tasks.checkTask(entry, True)

        if exitCode:
            self.log.error("Error: backup task %s exited with %d" %
                           (cn, exitCode))
        else:
            self.log.info("Backup task %s completed successfully" % (cn))

        self.dn = dn
        self.entry = entry

        return exitCode

    def bak2db(self, bename=None, backup_dir=None, args=None):
        '''
        Restore a backup by creating a bak2db task

        @param bename - 'commonname'/'cn' of the backend (e.g. 'userRoot')
        @param backup_dir - backup directory
        @param args - is a dictionary that contains modifier of the task
                wait: True/[False] - If True,  waits for the completion of
                                     the task before to return

        @return exit code

        @raise ValueError: if bename name does not exist
        '''

        # Checking the parameters
        if not backup_dir:
            raise ValueError("You must specify a backup directory")
        if not os.path.exists(backup_dir):
            raise ValueError("Backup file (%s) does not exist" % backup_dir)

        # If a backend name was provided then verify it
        if bename:
            ents = self.conn.mappingtree.list(bename=bename)
            if len(ents) != 1:
                raise ValueError("invalid backend name: %s" % bename)

        # build the task entry
        cn = "restore_" + time.strftime("%m%d%Y_%H%M%S", time.localtime())
        dn = "cn=%s,%s" % (cn, DN_RESTORE_TASK)
        entry = Entry(dn)
        entry.update({
            'objectclass': ['top', 'extensibleObject'],
            'cn': cn,
            'nsArchiveDir': backup_dir,
            'nsDatabaseType': 'ldbm database'
        })
        if bename:
            entry.update({'nsInstance': bename})

        # start the task and possibly wait for task completion
        try:
            self.conn.add_s(entry)
        except ldap.ALREADY_EXISTS:
            self.log.error("Fail to add the backup task (%s)" % dn)
            return -1

        exitCode = 0
        if args and args.get(TASK_WAIT, False):
            (done, exitCode) = self.conn.tasks.checkTask(entry, True)

        if exitCode:
            self.log.error("Error: restore task %s exited with %d" %
                           (cn, exitCode))
        else:
            self.log.info("Restore task %s completed successfully" % (cn))

        self.dn = dn
        self.entry = entry

        return exitCode

    def reindex(self, suffix=None, benamebase=None, attrname=None, args=None):
        '''
        Reindex a 'suffix' (or 'benamebase' that stores that suffix) for a
        given 'attrname'.  It uses an internal task to acheive this request.

        If 'suffix' and 'benamebase' are specified, it uses 'benamebase' first
        else 'suffix'.
        If both 'suffix' and 'benamebase' are missing it raise ValueError

        @param suffix - suffix of the backend
        @param benamebase - 'commonname'/'cn' of the backend (e.g. 'userRoot')
        @param attrname - attribute name
        @param args - is a dictionary that contains modifier of the reindex
                      task
                wait: True/[False] - If True, 'index' waits for the completion
                                     of the task before to return

        @return None

        @raise ValueError - if invalid missing benamebase and suffix or invalid
                            benamebase
        @raise LDAPError if unable to search for index names

        '''
        if not benamebase and not suffix:
            raise ValueError("Specify either bename or suffix")

        # If backend name was provided, retrieve the suffix
        if benamebase:
            ents = self.conn.mappingtree.list(bename=benamebase)
            if len(ents) != 1:
                raise ValueError("invalid backend name: %s" % benamebase)

            attr_suffix = MT_PROPNAME_TO_ATTRNAME[MT_SUFFIX]
            if not ents[0].hasAttr(attr_suffix):
                raise ValueError(
                    "invalid backend name: %s, or entry without %s" %
                    (benamebase, attr_suffix))

            suffix = ents[0].getValue(attr_suffix)

        entries_backend = self.conn.backend.list(suffix=suffix)
        backend = entries_backend[0].cn  # assume 1 local backend
        attrs = []

        if not attrname:
            #
            # Reindex all attributes - gather them first...
            #
            cn = "index_all_%s" % (time.strftime("%m%d%Y_%H%M%S",
                                                 time.localtime()))
            dn = ('cn=%s,cn=ldbm database,cn=plugins,cn=config' % backend)
            try:
                indexes = self.conn.search_s(dn,
                                             ldap.SCOPE_SUBTREE,
                                             '(objectclass=nsIndex)')
                for index in indexes:
                    attrs.append(index.getValue('cn'))
            except ldap.LDAPError:
                raise
        else:
            #
            # Reindex specific attribute
            #
            cn = "index_%s_%s" % (attrname, time.strftime("%m%d%Y_%H%M%S",
                                                          time.localtime()))
            attrs.append(attrname)

        dn = "cn=%s,%s" % (cn, DN_INDEX_TASK)
        entry = Entry(dn)
        entry.update({
            'objectclass': ['top', 'extensibleObject'],
            'cn': cn,
            'nsIndexAttribute': attrs,
            'nsInstance': backend
        })

        # start the task and possibly wait for task completion
        try:
            self.conn.add_s(entry)
        except ldap.ALREADY_EXISTS:
            self.log.error("Fail to add the index task for %s" % attrname)
            return -1

        exitCode = 0
        if args and args.get(TASK_WAIT, False):
            (done, exitCode) = self.conn.tasks.checkTask(entry, True)

        if exitCode:
            self.log.error("Error: index task %s exited with %d" %
                           (cn, exitCode))
        else:
            self.log.info("Index task %s completed successfully" % (cn))

        self.dn = dn
        self.entry = entry

        return exitCode

    def fixupMemberOf(self, suffix=None, benamebase=None, filt=None,
                      args=None):
        '''
            Trigger a fixup task on 'suffix' (or 'benamebase' that stores that
            suffix) related to the entries 'memberof' of groups. It uses an
            internal task to acheive this request.

            If 'suffix' and 'benamebase' are specified, it uses 'benamebase'
            first else 'suffix'.
            If both 'suffix' and 'benamebase' are missing it raise ValueError

            'filt' is a filter that will select all the entries (under
            'suffix') that we need to evaluate/fix.  If missing, the default
            value is "(|(objectclass=inetuser)(objectclass=inetadmin))"

            @param suffix - suffix of the backend
            @param benamebase - 'commonname'/'cn' of the backend
                                (e.g. 'userRoot')
            @param args - is a dictionary that contains modifier of the
                          fixupMemberOf task
                wait: True/[False] - If True,  waits for the completion of the
                                     task before to return

            @return exit code

            @raise ValueError: if benamebase and suffix are specified, or can
                               not retrieve the suffix from the mapping tree
                               entry
        '''
        if not benamebase and not suffix:
            raise ValueError("Specify either bename or suffix")

        # If backend name was provided, retrieve the suffix
        if benamebase:
            ents = self.conn.mappingtree.list(bename=benamebase)
            if len(ents) != 1:
                raise ValueError("invalid backend name: %s" % benamebase)

            attr = MT_PROPNAME_TO_ATTRNAME[MT_SUFFIX]
            if not ents[0].hasAttr(attr):
                raise ValueError(
                    "invalid backend name: %s, or entry without %s" %
                    (benamebase, attr))

            suffix = ents[0].getValue(attr)

        cn = "fixupmemberof_" + time.strftime("%m%d%Y_%H%M%S",
                                              time.localtime())
        dn = "cn=%s,%s" % (cn, DN_MBO_TASK)
        entry = Entry(dn)
        entry.setValues('objectclass', 'top', 'extensibleObject')
        entry.setValues('cn', cn)
        entry.setValues('basedn', suffix)
        if filt:
            entry.setValues('filter', filt)

        # start the task and possibly wait for task completion
        try:
            self.conn.add_s(entry)
        except ldap.ALREADY_EXISTS:
            self.log.error("Fail to add the memberOf fixup task")
            return -1

        exitCode = 0
        if args and args.get(TASK_WAIT, False):
            (done, exitCode) = self.conn.tasks.checkTask(entry, True)

        if exitCode:
            self.log.error(
                "Error: fixupMemberOf task %s for basedn %s exited with %d" %
                (cn, suffix, exitCode))
        else:
            self.log.info(
                "fixupMemberOf task %s for basedn %s completed successfully" %
                (cn, suffix))

        self.dn = dn
        self.entry = entry

        return exitCode

    def fixupTombstones(self, bename=None, args=None):
        '''
            Trigger a tombstone fixup task on the specified backend

            @param bename - 'commonname'/'cn' of the backend (e.g. 'userRoot').
                            Optional.
            @param args - is a dictionary that contains modifier of the task
                wait: True/[False] - If True,  waits for the completion of the
                                     task before to return

            @return exit code

            @raise ValueError: if bename name does not exist
        '''

        if not bename:
            bename = DEFAULT_BENAME

        # Verify the backend name
        if bename:
            ents = self.conn.mappingtree.list(bename=bename)
            if len(ents) != 1:
                raise ValueError("invalid backend name: %s" % bename)

        cn = "fixupTombstone_" + time.strftime("%m%d%Y_%H%M%S",
                                               time.localtime())
        dn = "cn=%s,%s" % (cn, DN_TOMB_FIXUP_TASK)
        entry = Entry(dn)
        entry.setValues('objectclass', 'top', 'extensibleObject')
        entry.setValues('cn', cn)
        entry.setValues('backend', bename)
        if args and args.get(TASK_TOMB_STRIP, False):
            entry.setValues('stripcsn', 'yes')

        # start the task and possibly wait for task completion
        try:
            self.conn.add_s(entry)
        except ldap.ALREADY_EXISTS:
            self.log.error("Fail to add the fixup tombstone task")
            return -1

        exitCode = 0
        if args and args.get(TASK_WAIT, False):
            (done, exitCode) = self.conn.tasks.checkTask(entry, True)

        if exitCode:
            self.log.error(
                "Error: tombstone fixup task %s for backend %s exited with %d"
                % (cn, bename, exitCode))
        else:
            self.log.info(
                "tombstone fixup task %s for backend %s completed successfully"
                % (cn, bename))

        self.dn = dn
        self.entry = entry

        return exitCode

    def automemberRebuild(self, suffix=DEFAULT_SUFFIX, scope='sub',
                          filterstr='objectclass=top', args=None):
        '''
        @param suffix - The suffix the task should examine - defualt is
                        "dc=example,dc=com"
        @param scope - The scope of the search to find entries
        @param fitlerstr - THe search filter to find entries
        @param args - is a dictionary that contains modifier of the task
                wait: True/[False] - If True,  waits for the completion of
                                     the task before to return
        @return exit code
        '''

        cn = 'task-' + time.strftime("%m%d%Y_%H%M%S", time.localtime())
        dn = ('cn=%s,cn=automember rebuild membership,cn=tasks,cn=config' % cn)

        entry = Entry(dn)
        entry.setValues('objectclass', 'top', 'extensibleObject')
        entry.setValues('cn', cn)
        entry.setValues('basedn', suffix)
        entry.setValues('filter', filterstr)
        entry.setValues('scope', scope)

        # start the task and possibly wait for task completion
        try:
            self.conn.add_s(entry)
        except ldap.ALREADY_EXISTS:
            self.log.error("Fail to add Automember Rebuild Membership task")
            return -1

        exitCode = 0
        if args and args.get(TASK_WAIT, False):
            (done, exitCode) = self.conn.tasks.checkTask(entry, True)

        if exitCode:
            self.log.error(
                "Error: Automember Rebuild Membership task (%s) exited with %d"
                % (cn, exitCode))
        else:
            self.log.info(
                "Automember Rebuild Membership task(%s) completed successfully"
                % (cn))

        self.dn = dn
        self.entry = entry

        return exitCode

    def automemberExport(self, suffix=DEFAULT_SUFFIX, scope='sub',
                         fstr='objectclass=top', ldif_out=None, args=None):
        '''
        @param suffix - The suffix the task should examine - default is
                        "dc=example,dc=com"
        @param scope - The scope of the search to find entries
        @param fstr - The search filter to find entries
        @param ldif_out - The name for the output LDIF file
        @param args - is a dictionary that contains modifier of the task
                wait: True/[False] - If True,  waits for the completion of
                                     the task before to return
        @return exit code
        @raise ValueError: if ldif_out is not provided
        '''

        if not ldif_out:
            raise ValueError("Missing ldif_out")

        cn = 'task-' + time.strftime("%m%d%Y_%H%M%S", time.localtime())
        dn = ('cn=%s,cn=automember export updates,cn=tasks,cn=config' % cn)
        entry = Entry(dn)
        entry.setValues('objectclass', 'top', 'extensibleObject')
        entry.setValues('cn', cn)
        entry.setValues('basedn', suffix)
        entry.setValues('filter', fstr)
        entry.setValues('scope', scope)
        entry.setValues('ldif', ldif_out)

        # start the task and possibly wait for task completion
        try:
            self.conn.add_s(entry)
        except ldap.ALREADY_EXISTS:
            self.log.error("Fail to add Automember Export Updates task")
            return -1

        exitCode = 0
        if args and args.get(TASK_WAIT, False):
            (done, exitCode) = self.conn.tasks.checkTask(entry, True)

        if exitCode:
            self.log.error(
                "Error: Automember Export Updates task (%s) exited with %d" %
                (cn, exitCode))
        else:
            self.log.info(
                "Automember Export Updates task (%s) completed successfully" %
                (cn))

        self.dn = dn
        self.entry = entry

        return exitCode

    def automemberMap(self, ldif_in=None, ldif_out=None, args=None):
        '''
        @param ldif_in - Entries to pass into the task for processing
        @param ldif_out - The resulting LDIF of changes from ldif_in
        @param args - is a dictionary that contains modifier of the task
                wait: True/[False] - If True,  waits for the completion
                                     of the task before to return
        @return exit code
        @raise ValueError: if ldif_out/ldif_in is not provided
        '''

        if not ldif_out or not ldif_in:
            raise ValueError("Missing ldif_out and/or ldif_in")

        cn = 'task-' + time.strftime("%m%d%Y_%H%M%S", time.localtime())
        dn = ('cn=%s,cn=automember map updates,cn=tasks,cn=config' % cn)

        entry = Entry(dn)
        entry.setValues('objectclass', 'top', 'extensibleObject')
        entry.setValues('cn', cn)
        entry.setValues('ldif_in', ldif_in)
        entry.setValues('ldif_out', ldif_out)

        # start the task and possibly wait for task completion
        try:
            self.conn.add_s(entry)
        except ldap.ALREADY_EXISTS:
            self.log.error("Fail to add Automember Map Updates task")
            return -1

        exitCode = 0
        if args and args.get(TASK_WAIT, False):
            (done, exitCode) = self.conn.tasks.checkTask(entry, True)

        if exitCode:
            self.log.error(
                "Error: Automember Map Updates task (%s) exited with %d" %
                (cn, exitCode))
        else:
            self.log.info(
                "Automember Map Updates task (%s) completed successfully" %
                (cn))

        self.dn = dn
        self.entry = entry

        return exitCode

    def fixupLinkedAttrs(self, linkdn=None, args=None):
        '''
        @param linkdn - The DN of linked attr config entry (if None all
                         possible configurations are checked)
        @param args - Is a dictionary that contains modifier of the task
                wait: True/[False] - If True,  waits for the completion
                                     of the task before to return
        @return exit code
        '''

        cn = 'task-' + time.strftime("%m%d%Y_%H%M%S", time.localtime())
        dn = ('cn=%s,cn=fixup linked attributes,cn=tasks,cn=config' % cn)
        entry = Entry(dn)
        entry.setValues('objectclass', 'top', 'extensibleObject')
        entry.setValues('cn', cn)
        if linkdn:
            entry.setValues('linkdn', linkdn)

        # start the task and possibly wait for task completion
        try:
            self.conn.add_s(entry)
        except ldap.ALREADY_EXISTS:
            self.log.error("Fail to add Fixup Linked Attributes task")
            return -1

        exitCode = 0
        if args and args.get(TASK_WAIT, False):
            (done, exitCode) = self.conn.tasks.checkTask(entry, True)

        if exitCode:
            self.log.error(
                "Error: Fixup Linked Attributes task (%s) exited with %d" %
                (cn, exitCode))
        else:
            self.log.info(
                "Fixup Linked Attributes task (%s) completed successfully" %
                (cn))

        self.dn = dn
        self.entry = entry

        return exitCode

    def schemaReload(self, schemadir=None, args=None):
        '''
        @param schemadir - The directory to look for schema files(optional)
        @param args - Is a dictionary that contains modifier of the task
                wait: True/[False] - If True,  waits for the completion of
                                     the task before to return
        @return exit code
        '''

        cn = 'task-' + time.strftime("%m%d%Y_%H%M%S", time.localtime())
        dn = ('cn=%s,cn=schema reload task,cn=tasks,cn=config' % cn)
        entry = Entry(dn)
        entry.setValues('objectclass', 'top', 'extensibleObject')
        entry.setValues('cn', cn)
        if schemadir:
            entry.setValues('schemadir', schemadir)

        # start the task and possibly wait for task completion
        try:
            self.conn.add_s(entry)
        except ldap.ALREADY_EXISTS:
            self.log.error("Fail to add Schema Reload task")
            return -1

        exitCode = 0
        if args and args.get(TASK_WAIT, False):
            (done, exitCode) = self.conn.tasks.checkTask(entry, True)

        if exitCode:
            self.log.error("Error: Schema Reload task (%s) exited with %d" %
                           (cn, exitCode))
        else:
            self.log.info("Schema Reload task (%s) completed successfully" %
                          (cn))

        self.dn = dn
        self.entry = entry

        return exitCode

    def fixupWinsyncMembers(self, suffix=DEFAULT_SUFFIX,
                            fstr='objectclass=top', args=None):
        '''
        @param suffix - The suffix the task should rebuild -
                        default is "dc=example,dc=com"
        @param fstr - The search filter to find entries
        @param args - is a dictionary that contains modifier of the task
                wait: True/[False] - If True,  waits for the completion of
                                     the task before to return
        @return exit code
        '''

        cn = 'task-' + time.strftime("%m%d%Y_%H%M%S", time.localtime())
        dn = ('cn=%s,cn=memberuid task,cn=tasks,cn=config' % cn)
        entry = Entry(dn)
        entry.setValues('objectclass', 'top', 'extensibleObject')
        entry.setValues('cn', cn)
        entry.setValues('basedn', suffix)
        entry.setValues('filter', fstr)

        # start the task and possibly wait for task completion
        try:
            self.conn.add_s(entry)
        except ldap.ALREADY_EXISTS:
            self.log.error("Fail to add fixupWinsyncMembers 'memberuid task'")
            return -1

        exitCode = 0
        if args and args.get(TASK_WAIT, False):
            (done, exitCode) = self.conn.tasks.checkTask(entry, True)

        if exitCode:
            self.log.error(
                "fixupWinsyncMembers 'memberuid task' (%s) exited with %d" %
                (cn, exitCode))
        else:
            self.log.info(
                "'memberuid task' (%s) completed successfully" % (cn))

        self.dn = dn
        self.entry = entry

        return exitCode

    def syntaxValidate(self, suffix=DEFAULT_SUFFIX, fstr='objectclass=top',
                       args=None):
        '''
        @param suffix - The suffix the task should validate -
                        default is "dc=example,dc=com"
        @param fstr - The search filter to find entries
        @param args - is a dictionary that contains modifier of the task
                wait: True/[False] - If True,  waits for the completion of the
                                     task before to return
        @return exit code
        '''

        cn = 'task-' + time.strftime("%m%d%Y_%H%M%S", time.localtime())
        dn = ('cn=%s,cn=syntax validate,cn=tasks,cn=config' % cn)
        entry = Entry(dn)
        entry.setValues('objectclass', 'top', 'extensibleObject')
        entry.setValues('cn', cn)
        entry.setValues('basedn', suffix)
        entry.setValues('filter', fstr)

        # start the task and possibly wait for task completion
        try:
            self.conn.add_s(entry)
        except ldap.ALREADY_EXISTS:
            self.log.error("Fail to add Syntax Validate task")
            return -1

        exitCode = 0
        if args and args.get(TASK_WAIT, False):
            (done, exitCode) = self.conn.tasks.checkTask(entry, True)

        if exitCode:
            self.log.error("Error: Syntax Validate (%s) exited with %d" %
                           (cn, exitCode))
        else:
            self.log.info("Syntax Validate task (%s) completed successfully" %
                          (cn))

        self.dn = dn
        self.entry = entry

        return exitCode

    def usnTombstoneCleanup(self, suffix=DEFAULT_SUFFIX, bename=None,
                            maxusn_to_delete=None, args=None):
        '''
        @param suffix - The suffix the task should cleanup - default is
                        "dc=example,dc=com"
        @param backend - The 'backend' the task should cleanup
        @param maxusn_to_delete - Maximum number of usn's to delete
        @param args - is a dictionary that contains modifier of the task
                wait: True/[False] - If True,  waits for the completion of
                                     the task before to return
        @return exit code
        '''

        cn = 'task-' + time.strftime("%m%d%Y_%H%M%S", time.localtime())
        dn = ('cn=%s,cn=USN tombstone cleanup task,cn=tasks,cn=config' % cn)
        entry = Entry(dn)
        entry.setValues('objectclass', 'top', 'extensibleObject')
        entry.setValues('cn', cn)
        if not bename:
            entry.setValues('suffix', suffix)
        else:
            entry.setValues('backend', bename)
        if maxusn_to_delete:
            entry.setValues('maxusn_to_delete')

        # start the task and possibly wait for task completion
        try:
            self.conn.add_s(entry)
        except ldap.ALREADY_EXISTS:
            self.log.error("Fail to add USN tombstone cleanup task")
            return -1

        exitCode = 0
        if args and args.get(TASK_WAIT, False):
            (done, exitCode) = self.conn.tasks.checkTask(entry, True)

        if exitCode:
            self.log.error(
                "Error: USN tombstone cleanup task (%s) exited with %d" %
                (cn, exitCode))
        else:
            self.log.info(
                "USN tombstone cleanup task (%s) completed successfully" %
                (cn))

        self.dn = dn
        self.entry = entry

        return exitCode

    def sysconfigReload(self, configfile=None, logchanges=None, args=None):
        '''
        @param configfile - The sysconfig file:
                            /etc/sysconfig/dirsrv-localhost
        @param logchanges - True/False - Tell the server to log the changes
                                         made by the task
        @param args - is a dictionary that contains modifier of the task
                wait: True/[False] - If True,  waits for the completion of the
                                     task before to return
        @return exit code
        @raise ValueError: If sysconfig file not provided
        '''

        if not configfile:
            raise ValueError("Missing required paramter: configfile")

        cn = 'task-' + time.strftime("%m%d%Y_%H%M%S", time.localtime())
        dn = ('cn=%s,cn=cn=sysconfig reload,cn=tasks,cn=config' % cn)
        entry = Entry(dn)
        entry.setValues('objectclass', 'top', 'extensibleObject')
        entry.setValues('cn', cn)
        entry.setValues('sysconfigfile', configfile)
        if logchanges:
            entry.setValues('logchanges', logchanges)
        # start the task and possibly wait for task completion
        try:
            self.conn.add_s(entry)
        except ldap.ALREADY_EXISTS:
            self.log.error("Fail to add Sysconfig Reload task")
            return -1

        exitCode = 0
        if args and args.get(TASK_WAIT, False):
            (done, exitCode) = self.conn.tasks.checkTask(entry, True)

        if exitCode:
            self.log.error("Error: Sysconfig Reload task (%s) exited with %d" %
                           (cn, exitCode))
        else:
            self.log.info("Sysconfig Reload task (%s) completed successfully" %
                          (cn))

        self.dn = dn
        self.entry = entry

        return exitCode

    def cleanAllRUV(self, suffix=None, replicaid=None, force=None, args=None):
        '''
        @param replicaid - The replica ID to remove/clean
        @param force - True/False - Clean all the replicas, even if one is down
        @param args - is a dictionary that contains modifier of the task
                wait: True/[False] - If True,  waits for the completion of the
                                     task before to return
        @return tuple (task dn, and the exit code)
        @raise ValueError: If missing replicaid
        '''

        if not replicaid:
            raise ValueError("Missing required paramter: replicaid")

        if not suffix:
            raise ValueError("Missing required paramter: suffix")

        cn = 'task-' + time.strftime("%m%d%Y_%H%M%S", time.localtime())
        dn = ('cn=%s,cn=cleanallruv,cn=tasks,cn=config' % cn)
        entry = Entry(dn)
        entry.setValues('objectclass', 'top', 'extensibleObject')
        entry.setValues('cn', cn)
        entry.setValues('replica-base-dn', suffix)
        entry.setValues('replica-id', replicaid)
        if force:
            entry.setValues('replica-force-cleaning', 'yes')
        # start the task and possibly wait for task completion
        try:
            self.conn.add_s(entry)
        except ldap.ALREADY_EXISTS:
            self.log.error("Fail to add cleanAllRUV task")
            return (dn, -1)

        exitCode = 0
        if args and args.get(TASK_WAIT, False):
            (done, exitCode) = self.conn.tasks.checkTask(entry, True)

        if exitCode:
            self.log.error("Error: cleanAllRUV task (%s) exited with %d" %
                           (cn, exitCode))
        else:
            self.log.info("cleanAllRUV task (%s) completed successfully" %
                          (cn))

        self.dn = dn
        self.entry = entry

        return (dn, exitCode)

    def abortCleanAllRUV(self, suffix=None, replicaid=None, certify=None,
                         args=None):
        '''
        @param replicaid - The replica ID to remove/clean
        @param certify - True/False - Certify the task was aborted on all
                                      the replicas
        @param args - is a dictionary that contains modifier of the task
                wait: True/[False] - If True,  waits for the completion of
                                     the task before to return
        @return tuple (task dn, and the exit code)
        @raise ValueError: If missing replicaid
        '''

        if not replicaid:
            raise ValueError("Missing required paramter: replicaid")
        if not suffix:
            raise ValueError("Missing required paramter: suffix")

        cn = 'task-' + time.strftime("%m%d%Y_%H%M%S", time.localtime())
        dn = ('cn=%s,cn=abort cleanallruv,cn=tasks,cn=config' % cn)
        entry = Entry(dn)
        entry.setValues('objectclass', 'top', 'extensibleObject')
        entry.setValues('cn', cn)
        entry.setValues('replica-base-dn', suffix)
        entry.setValues('replica-id', replicaid)
        if certify:
            entry.setValues('replica-certify-all', 'yes')
        else:
            entry.setValues('replica-certify-all', 'no')

        # start the task and possibly wait for task completion
        try:
            self.conn.add_s(entry)
        except ldap.ALREADY_EXISTS:
            self.log.error("Fail to add Abort cleanAllRUV task")
            return (dn, -1)

        exitCode = 0
        if args and args.get(TASK_WAIT, False):
            (done, exitCode) = self.conn.tasks.checkTask(entry, True)

        if exitCode:
            self.log.error(
                "Error: Abort cleanAllRUV task (%s) exited with %d" %
                (cn, exitCode))
        else:
            self.log.info(
                "Abort cleanAllRUV task (%s) completed successfully" %
                (cn))

        self.dn = dn
        self.entry = entry

        return (dn, exitCode)

    def upgradeDB(self, nsArchiveDir=None, nsDatabaseType=None,
                  nsForceToReindex=None, args=None):
        '''
        @param nsArchiveDir - The archive directory
        @param nsDatabaseType - The database type - default is "ldbm database"
        @param nsForceToReindex - True/False - force reindexing to occur
        @param args - is a dictionary that contains modifier of the task
                wait: True/[False] - If True,  waits for the completion of the
                                     task before to return
        @return exit code
        @raise ValueError: If missing nsArchiveDir
        '''

        if not nsArchiveDir:
            raise ValueError("Missing required paramter: nsArchiveDir")

        cn = 'task-' + time.strftime("%m%d%Y_%H%M%S", time.localtime())
        dn = ('cn=%s,cn=upgradedb,cn=tasks,cn=config' % cn)
        entry = Entry(dn)
        entry.setValues('objectclass', 'top', 'extensibleObject')
        entry.setValues('cn', cn)
        entry.setValues('nsArchiveDir', nsArchiveDir)
        if nsDatabaseType:
            entry.setValues('nsDatabaseType', nsDatabaseType)
        if nsForceToReindex:
            entry.setValues('nsForceToReindex', 'True')

        # start the task and possibly wait for task completion
        try:
            self.conn.add_s(entry)
        except ldap.ALREADY_EXISTS:
            self.log.error("Fail to add upgradedb task")
            return -1

        exitCode = 0
        if args and args.get(TASK_WAIT, False):
            (done, exitCode) = self.conn.tasks.checkTask(entry, True)

        if exitCode:
            self.log.error("Error: upgradedb task (%s) exited with %d" %
                           (cn, exitCode))
        else:
            self.log.info("Upgradedb task (%s) completed successfully" % (cn))

        self.dn = dn
        self.entry = entry

        return exitCode
