"""Git-backed tests for modified-only lint selection."""

import os
import subprocess

from bellybutton import cli


def git(directory, *arguments):
    subprocess.check_call(['git', '-C', str(directory)] + list(arguments))


def make_repo(tmpdir):
    source = tmpdir.mkdir('source')
    git(source, 'init')
    git(source, 'symbolic-ref', 'HEAD', 'refs/heads/master')
    git(source, 'config', 'user.name', 'Bellybutton Test')
    git(source, 'config', 'user.email', 'test@example.invalid')

    for name in ('deleted.py', 'renamed.py', 'changed.py'):
        source.join(name).write('value = 1\n')
    os.symlink('renamed.py', str(source.join('linked.py')))
    source.join('.bellybutton.yml').write(
        'default_settings: !settings\n'
        '  included: ["*"]\n'
        '  excluded: []\n'
        '  allow_ignore: no\n'
        'rules:\n'
        '  NoPrint:\n'
        '    description: Print calls are forbidden.\n'
        '    expr: //Call[func/Name/@id="print"]\n'
    )
    git(source, 'add', '.')
    git(source, 'commit', '-m', 'Initial files')

    remote = tmpdir.join('remote.git')
    subprocess.check_call(['git', 'clone', '--bare', str(source), str(remote)])
    work = tmpdir.join('work')
    subprocess.check_call(['git', 'clone', str(remote), str(work)])
    git(work, 'config', 'user.name', 'Bellybutton Test')
    git(work, 'config', 'user.email', 'test@example.invalid')
    git(work, 'checkout', '-b', 'feature')
    return work


def test_modified_only_lints_rename_destination_and_skips_deleted_path(tmpdir, capsys):
    work = make_repo(tmpdir)
    git(work, 'rm', 'deleted.py')
    git(work, 'mv', 'renamed.py', 'new.py')
    work.join('new.py').write('print("bad")\n')
    git(work, 'add', 'new.py')
    work.join('changed.py').write('value = 2\n')
    git(work, 'add', 'changed.py')

    assert cli.get_git_modified(str(work)) == {
        str(work.join('new.py')), str(work.join('changed.py'))
    }
    assert cli.lint(modified_only=True, project_directory=str(work)) == 1
    assert 'new.py:1\tNoPrint' in capsys.readouterr()[0]


def test_modified_only_includes_branch_commits_relative_to_base(tmpdir):
    work = make_repo(tmpdir)
    git(work, 'rm', 'deleted.py')
    git(work, 'mv', 'renamed.py', 'new.py')
    work.join('new.py').write('print("bad")\n')
    git(work, 'add', 'new.py')
    git(work, 'commit', '-m', 'Rename and delete Python files')

    assert cli.get_git_modified(str(work)) == {str(work.join('new.py'))}


def test_modified_only_keeps_git_quoted_python_names(tmpdir):
    work = make_repo(tmpdir)
    unusual_name = 'renamed\nfile.py'
    git(work, 'mv', 'renamed.py', unusual_name)

    assert cli.get_git_modified(str(work)) == {str(work.join(unusual_name))}


def test_modified_only_resolves_paths_from_subproject(tmpdir):
    work = make_repo(tmpdir)
    subproject = work.mkdir('subproject')
    subproject.join('new.py').write('value = 2\n')
    git(work, 'add', 'subproject/new.py')
    work.join('changed.py').write('value = 2\n')
    git(work, 'add', 'changed.py')

    assert cli.get_git_modified(str(subproject)) == {str(subproject.join('new.py'))}


def test_modified_only_includes_type_changed_python_files(tmpdir):
    work = make_repo(tmpdir)
    git(work, 'rm', 'linked.py')
    work.join('linked.py').write('print("bad")\n')
    git(work, 'add', 'linked.py')

    assert cli.get_git_modified(str(work)) == {str(work.join('linked.py'))}


def test_modified_only_includes_unmerged_python_files(tmpdir):
    work = make_repo(tmpdir)
    work.join('changed.py').write('value = 2\n')
    git(work, 'add', 'changed.py')
    git(work, 'commit', '-m', 'Change feature value')

    source = tmpdir.join('source')
    source.join('changed.py').write('value = 3\n')
    git(source, 'add', 'changed.py')
    git(source, 'commit', '-m', 'Change master value')
    git(source, 'remote', 'add', 'origin', str(tmpdir.join('remote.git')))
    git(source, 'push', 'origin', 'master')

    git(work, 'fetch', 'origin')
    git(work, 'checkout', 'master')
    git(work, 'reset', '--hard', 'origin/master')
    assert subprocess.call(['git', '-C', str(work), 'merge', 'feature']) != 0

    assert cli.get_git_modified(str(work)) == {str(work.join('changed.py'))}


def test_modified_only_decodes_non_utf8_git_names(tmpdir, monkeypatch):
    monkeypatch.setattr(cli.subprocess, 'check_call', lambda _: None)
    monkeypatch.setattr(
        cli.subprocess, 'check_output',
        lambda _: b'notes_\xff.txt\0good.py\0'
    )

    assert cli.get_git_modified(str(tmpdir)) == {str(tmpdir.join('good.py'))}


def test_python_two_fallback_decodes_valid_unicode_names(monkeypatch):
    monkeypatch.setattr(cli.os, 'fsdecode', None, raising=False)
    monkeypatch.setattr(cli.sys, 'getfilesystemencoding', lambda: 'utf-8')

    assert cli._decode_git_path(b'caf\xc3\xa9.py') == u'caf\u00e9.py'
    assert cli._decode_git_path(b'notes_\xff.txt') == b'notes_\xff.txt'


def test_python_two_fallback_fails_lint_for_undecodable_python_path(
        tmpdir, monkeypatch, capsys):
    work = make_repo(tmpdir)
    monkeypatch.setattr(cli.os, 'fsdecode', None, raising=False)
    monkeypatch.setattr(cli.sys, 'getfilesystemencoding', lambda: 'utf-8')
    monkeypatch.setattr(cli.subprocess, 'check_call', lambda _: None)
    monkeypatch.setattr(
        cli.subprocess, 'check_output',
        lambda _: b'bad_\xff.py\0'
    )

    assert cli.lint(modified_only=True, project_directory=str(work)) == 1
    assert 'Cannot decode modified Python path' in capsys.readouterr()[0]
