"""Adds the HyTeg framework as a project to VaRA-TS."""
import logging
import os
import typing as tp

import benchbuild as bb
from benchbuild.command import WorkloadSet, SourceRoot
from benchbuild.utils.cmd import ninja, cmake, mkdir
from benchbuild.utils.revision_ranges import SingleRevision
from benchbuild.utils.settings import get_number_of_jobs
from plumbum import local

from varats.experiment.workload_util import WorkloadCategory, RSBinary
from varats.paper.paper_config import PaperConfigSpecificGit
from varats.project.project_domain import ProjectDomains
from varats.project.project_util import (
    get_local_project_git_path,
    BinaryType,
    ProjectBinaryWrapper,
)
from varats.project.sources import FeatureSource
from varats.project.varats_command import VCommand
from varats.project.varats_project import VProject
from varats.utils.git_commands import init_all_submodules, update_all_submodules
from varats.utils.git_util import ShortCommitHash, RevisionBinaryMap
from varats.utils.settings import bb_cfg

LOG = logging.getLogger(__name__)


class HyTeg(VProject):
    """
    C++ framework for large scale high performance finite element simulations
    based on (but not limited to) matrix-free geometric multigrid.

    Note:
        Currently HyTeg CANNOT be compiled with the Phasar passes activated
        in vara.
        Trying to do so will crash the compiler

        If you use Dune with an experiment that uses the vara compiler,
        add `-mllvm --vara-disable-phasar` to the projects `cflags` to
        disable phasar passes.
        This will still allow to analyse compile-time variability.
    """
    NAME = 'HyTeg'
    GROUP = 'cpp_projects'
    DOMAIN = ProjectDomains.HPC

    SOURCE = [
        PaperConfigSpecificGit(
            project_name="HyTeg",
            remote="https://github.com/se-sic/hyteg-VaRA.git",
            local="HyTeg",
            refspec="origin/HEAD",
            limit=None,
            shallow=False
        ),
        FeatureSource()
    ]

    WORKLOADS = {
        WorkloadSet(WorkloadCategory.EXAMPLE): [
            VCommand(
                SourceRoot("HyTeg") / "build" / "apps" / "profiling" /
                RSBinary('ProfilingApp'),
                label='ProfilingApp'
            )
        ]
    }

    @staticmethod
    def binaries_for_revision(
        revision: ShortCommitHash
    ) -> tp.List['ProjectBinaryWrapper']:
        binaries = RevisionBinaryMap(get_local_project_git_path(HyTeg.NAME))

        binaries.specify_binary(
            "ProfilingApp",
            BinaryType.EXECUTABLE,
            only_valid_in=SingleRevision(
                "f4711dadc3f61386e6ccdc704baa783253332db2"
            )
        )

        return binaries[revision]

    def compile(self) -> None:
        """Compile HyTeg with irrelevant settings disabled."""
        hyteg_source = local.path(self.source_of(self.primary_source))

        mkdir("-p", hyteg_source / "build")

        update_all_submodules(hyteg_source, recursive=True, init=True)

        cc_compiler = bb.compiler.cc(self)
        cxx_compiler = bb.compiler.cxx(self)

        cmake_args = [
            "-G", "Ninja", "..", "-DWALBERLA_BUILD_WITH_MPI=OFF",
            "-DHYTEG_BUILD_DOC=OFF"
        ]

        if (eigen_path := os.getenv("EIGEN_PATH")):
            cmake_args.append(f"-DEIGEN_DIR={eigen_path}")
            print("EIGEN_DIR SET")
        else:
            LOG.warning(
                "EIGEN_PATH environment variable not set! This will cause compilation errors when using "
                "configurations"
            )
            print("EIGEN_PATH Environment variable not set!!!")

        print(cmake_args)

        with local.cwd(hyteg_source / "build"):
            with local.env(CC=str(cc_compiler), CXX=str(cxx_compiler)):
                bb.watch(cmake)(*cmake_args)

                with local.cwd(hyteg_source / "build"):
                    bb.watch(ninja)("ProfilingApp")

    def recompile(self) -> None:
        """Recompiles HyTeg e.g. after a patch has been applied."""
        hyteg_source = local.path(self.source_of(self.primary_source))

        with local.cwd(hyteg_source / "build"):
            bb.watch(ninja)("ProfilingApp")

    def run_tests(self) -> None:
        pass
