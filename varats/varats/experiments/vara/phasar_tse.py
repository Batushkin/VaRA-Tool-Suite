"""
Implements the TSE experiment.

The experiment analyses a project with VaRA's feature taint analysis and
PhASAR's symbolic execution.
"""

import typing as tp

from benchbuild.utils import actions
from benchbuild.project import Project
from benchbuild.utils.actions import Step
from benchbuild.extensions import compiler, run, time
from benchbuild.utils.cmd import opt

from plumbum import local

from varats.experiment.experiment_util import (
    exec_func_with_pe_error_handler,
    VersionExperiment,
    wrap_unlimit_stack_size,
    get_varats_result_folder,
    ExperimentHandle,
    get_default_compile_error_wrapped,
    create_default_compiler_error_handler,
    create_default_analysis_failure_handler,
    create_new_success_result_filepath,
)
from varats.experiment.wllvm import (
    RunWLLVM,
    BCFileExtensions,
    get_bc_cache_actions,
    get_cached_bc_file_path,
)

from varats.experiments.vara.phasar_fta import PhASARFTACheck

from varats.project.varats_project import VProject
from varats.report.report import ReportSpecification
from varats.data.reports.empty_report import EmptyReport
from varats.data.reports.feature_analysis_report import FeatureAnalysisReport as FAR

class PSECheck(actions.ProjectStep):  # type: ignore
  """Analyse a project with PhASAR Symbolic Execution"""

  NAME = "PSECheck"
  DESCRIPTION = "Execute PhASAR SE."

  project: VProject

  def __init__(
    self,
    project: Project,
    experiment_handle: ExperimentHandle,
    bc_file_extensions: tp.List[BCFileExtensions],
  ):
    super().__init__(project=project)
    self.__bc_file_extensions = bc_file_extensions
    self.__experiment_handle = experiment_handle

  def __call__(self) -> actions.StepResult:
    return self.analyze()

  def analyze(self) -> actions.StepResult:
    """This step runs PhASAR SE"""

    # Define the output directory.
    vara_result_folder = get_varats_result_folder(self.project)

    for binary in self.project.binaries:
      # Define empty success file
      result_file = create_new_success_result_filepath(
        self.__experiment_handle, EmptyReport, self.project, binary
      )

      # Combine the input bitcode file's name
      bc_target_file = get_cached_bc_file_path(
        self.project, binary, self.__bc_file_extensions
      )

      # Hardcoded until VaRA upgrades to newer PhASAR version
      se = local["/home/hristo/Public/MA/phasar/build/tools/symbolic-executor/se"]
      run_cmd = se[str(bc_target_file),]
      run_cmd = wrap_unlimit_stack_size(run_cmd)
      run_cmd = run_cmd > f'{result_file}'

      # Run the command with custom error handler and timeout
      exec_func_with_pe_error_handler(
        run_cmd,
        create_default_analysis_failure_handler(
          self.__experiment_handle, self.project, EmptyReport
        )
      )

    return actions.StepResult.OK



class TaintedSymbolicExecution(VersionExperiment, shorthand="TSE"):
  """Generates a tainted symbolic execution analysis of the project specified in the call"""

  NAME = "TaintedSymbolicExecution"
  REPORT_SPEC = ReportSpecification(EmptyReport, FAR)

  def actions_for_project(self, project: Project) -> tp.List[actions.Step]:
    # Add the required runtime extensions to the project(s).
    project.runtime_extension = run.RuntimeExtension(project, self) \
      << time.RunWithTime()

    # Add the required compiler extensions to the project(s).
    project.compiler_extension = compiler.RunCompiler(project, self) \
      << RunWLLVM() \
      << run.WithTimeout()
    
    # Add own error handler to compile step.
    project.compile = get_default_compile_error_wrapped(
      self.get_handle(), project, self.REPORT_SPEC.main_report
    )

    bc_file_extensions = [
      BCFileExtensions.NO_OPT, BCFileExtensions.TBAA,
      BCFileExtensions.FEATURE, BCFileExtensions.DEBUG
    ]

    analysis_actions = []

    analysis_actions += get_bc_cache_actions(
      project,
      bc_file_extensions,
      extraction_error_handler=create_default_compiler_error_handler(
        self.get_handle(), project, self.REPORT_SPEC.main_report
      )
    )

    analysis_actions.append(
      PSECheck(project, self.get_handle(), bc_file_extensions)
    )

    analysis_actions.append(
      PhASARFTACheck(project, self.get_handle(), bc_file_extensions)
    )

    analysis_actions.append(actions.Clean(project))

    return analysis_actions