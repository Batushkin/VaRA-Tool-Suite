"""Project file for Simplus"""
import typing as tp
from pathlib import Path

import benchbuild as bb
from benchbuild.utils.cmd import cmake
from benchbuild.utils.settings import get_number_of_jobs
from plumbum import local

from varats.paper.paper_config import PaperConfigSpecificGit
from varats.project.project_domain import ProjectDomains
from varats.project.project_util import (
    BinaryType,
    ProjectBinaryWrapper,
    get_local_project_git_path,
    verify_binaries,
    get_tagged_commits,
)
from varats.project.varats_project import VProject
from varats.provider.release.release_provider import (
    ReleaseProviderHook,
    ReleaseType,
)
from varats.utils.git_util import (
    RevisionBinaryMap,
    ShortCommitHash,
    FullCommitHash,
)
from varats.utils.settings import bb_cfg

class Simplus(VProject):
    """Simple test project for Symbolic Performance Execution"""

    NAME = 'simplus'
    GROUP = 'cpp_projects'
    DOMAIN = ProjectDomains.TEST

    SOURCE = [
        PaperConfigSpecificGit(
            project_name="simplus",
            remote="https://github.com/Batushkin/simplus.git",
            local="simplus",
            refspec="origin/HEAD",
            limit=None,
            shallow=False
        )
    ]

    @staticmethod
    def binaries_for_revision(
        revision: ShortCommitHash
    ) -> tp.List[ProjectBinaryWrapper]:
        binary_map = RevisionBinaryMap(get_local_project_git_path(Simplus.NAME))
        binary_map.specify_binary('build/simplus', BinaryType.EXECUTABLE)

        return binary_map[revision]
    
    def run_tests(self) -> None:
        """ This function defines tests and benchmarks for the project. """
        pass

    def compile(self) -> None:
        """ Compile the project. """
        simplus_source = Path(self.source_of(self.primary_source))

        cxx_compiler = bb.compiler.cxx(self)

        (simplus_source / "build").mkdir(parents=True, exist_ok=True)

        with local.cwd(simplus_source / "build"):
            with local.env(CXX=str(cxx_compiler)):
                bb.watch(cmake)("-G", "Unix Makefiles", "../")

            bb.watch(cmake)("--build", ".", "-j", get_number_of_jobs(bb_cfg()))

        with local.cwd(simplus_source):
            verify_binaries(self)
