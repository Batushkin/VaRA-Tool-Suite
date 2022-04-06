import math
import typing as tp

import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
from matplotlib import style
from pandas import DataFrame
from pygtrie import CharTrie

from varats.data.databases.blame_library_interactions_database import (
    BlameLibraryInteractionsDatabase,
)
from varats.data.databases.survivng_lines_database import SurvivingLinesDatabase
from varats.mapping.commit_map import get_commit_map, CommitMap
from varats.paper.case_study import CaseStudy
from varats.plot.plot import Plot
from varats.plot.plots import PlotGenerator, PlotConfig, REQUIRE_CASE_STUDY
from varats.utils.git_util import (
    ShortCommitHash,
    FullCommitHash,
    create_commit_lookup_helper,
)


def get_lines_per_commit_long(case_study: CaseStudy) -> DataFrame:
    project_name = case_study.project_name
    data = SurvivingLinesDatabase.get_data_for_project(
        project_name, ["revision", "commit_hash", "lines"],
        get_commit_map(project_name), case_study
    )

    def cs_filter(data_frame: DataFrame) -> DataFrame:
        """Filter out all commits that are not in the case study if one was
        selected."""
        if case_study is None or data_frame.empty:
            return data_frame
        # use a trie for fast prefix lookup
        revisions = CharTrie()
        for revision in case_study.revisions:
            revisions[revision.hash] = True
        return data_frame[data_frame["commit_hash"].
                          apply(lambda x: revisions.has_node(x) != 0)]

    return cs_filter(data)


def get_normalized_lines_per_commit_long(case_study: CaseStudy) -> DataFrame:
    data = get_lines_per_commit_long(case_study)
    starting_lines = {
        commit_hash: lines
        for revision, commit_hash, lines in data.itertuples(index=False)
        if revision == FullCommitHash(commit_hash).to_short_commit_hash() and
        lines is not math.nan
    }
    data = data.apply(
        lambda x: [
            x['revision'], x['commit_hash'],
            (x['lines'] * 100 / starting_lines[x['commit_hash']])
            if starting_lines.__contains__(x['commit_hash']) else math.nan
        ],
        axis=1,
        result_type='broadcast'
    )
    return data.rename(columns={'commit_hash': 'base_hash'})


def get_normalized_lines_per_commit_wide(case_study: CaseStudy) -> DataFrame:
    case_study_data = get_normalized_lines_per_commit_long(case_study)
    case_study_data = case_study_data.pivot(
        index="base_hash", columns='revision', values='lines'
    )
    cmap = get_commit_map(case_study.project_name)
    case_study_data = case_study_data.sort_index(
        key=lambda x: x.map(lambda y: cmap.short_time_id(ShortCommitHash(y)))
    )
    case_study_data = case_study_data.sort_index(
        axis=1, key=lambda x: x.map(cmap.short_time_id)
    )
    return case_study_data.astype(float)


def get_interactions_per_commit_long(case_study: CaseStudy):
    project_name = case_study.project_name
    data: DataFrame = BlameLibraryInteractionsDatabase().get_data_for_project(
        project_name, ["base_hash", "amount", "revision"],
        get_commit_map(project_name), case_study
    )
    data = data.groupby(["base_hash", "revision"],
                        sort=False).sum().reset_index()

    def cs_filter(data_frame: DataFrame) -> DataFrame:
        """Filter out all commits that are not in the case study if one was
        selected."""
        if case_study is None or data_frame.empty:
            return data_frame
        # use a trie for fast prefix lookup
        revisions = CharTrie()
        for revision in case_study.revisions:
            revisions[revision.hash] = True
        return data_frame[
            data_frame["base_hash"].apply(lambda x: revisions.has_node(x) != 0)]

    return cs_filter(data)


def get_normalized_interactions_per_commit_long(
    case_study: CaseStudy
) -> DataFrame:
    data = get_interactions_per_commit_long(case_study)
    max_interactions = data.drop(columns=["revision"]
                                ).groupby("base_hash").max()
    data = data.apply(
        lambda x: [
            x['base_hash'], x['revision'],
            (x['amount'] * 100 / max_interactions['amount'][x['base_hash']])
            if max_interactions['amount'][x['base_hash']] is not math.nan else
            math.nan
        ],
        axis=1,
        result_type='broadcast'
    )
    return data.rename(columns={'amount': 'interactions'})


def get_normalized_interactions_per_commit_wide(
    case_study: CaseStudy
) -> DataFrame:
    data = get_normalized_interactions_per_commit_long(case_study)
    data = data.pivot(
        index="base_hash", columns="revision", values="interactions"
    )
    cmap = get_commit_map(case_study.project_name)
    data = data.sort_index(
        key=lambda x: x.map(lambda y: cmap.short_time_id(ShortCommitHash(y)))
    )
    data = data.sort_index(axis=1, key=lambda x: x.map(cmap.short_time_id))
    return data.astype(float)


def lines_and_interactions(case_study: CaseStudy) -> DataFrame:
    lines: DataFrame = get_normalized_lines_per_commit_long(case_study)

    interactions: DataFrame = get_normalized_interactions_per_commit_long(
        case_study
    )
    data = lines.merge(interactions, how='left', on=["base_hash", "revision"])
    data.dropna(
        axis=0, how='any', inplace=True, subset=["lines", "interactions"]
    )
    data.insert(3, "space", np.nan)
    data = data.pivot(
        index="base_hash",
        columns="revision",
        values=["lines", "interactions", 'space']
    )
    data = data.stack(level=0, dropna=False)
    cmap = get_commit_map(case_study.project_name)
    data = data.sort_index(
        level=0,
        key=lambda x: x.map(lambda y: cmap.short_time_id(ShortCommitHash(y)))
    )
    data = data.sort_index(axis=1, key=lambda x: x.map(cmap.short_time_id))
    return data.astype(float)


def get_author_color_map(case_study: CaseStudy) -> dict[tp.Any, tp.Any]:
    commit_lookup_helper = create_commit_lookup_helper(case_study.project_name)
    author_set: set = set()
    for commit_hash in case_study.revisions:
        commit = commit_lookup_helper(commit_hash)
        author_set.add(commit.author.name)
    author_list = list(author_set)
    colormap = plt.get_cmap("nipy_spectral")
    colors = colormap(np.linspace(0, 1, len(author_list)))
    return dict(zip(author_list, colors))


class HeatMapPlot(Plot, plot_name=None):
    colormap = 'RdYlGn'
    vmin = 0
    vmax = 100
    xticklables = 1
    yticklables = 1

    def __init__(
        self, name: str, plot_config: PlotConfig,
        data_function: tp.Callable[[CaseStudy], DataFrame], **kwargs
    ):
        super().__init__(name, plot_config, **kwargs)
        self.color_commits = False
        self.data_function = data_function

    def plot(self, view_mode: bool) -> None:
        style.use(self.plot_config.style())
        _, axis = plt.subplots(1, 1)
        case_study = self.plot_kwargs['case_study']
        data = self.data_function(case_study)
        axis = sns.heatmap(
            data,
            cmap=self.colormap,
            vmin=self.vmin,
            vmax=self.vmax,
            xticklabels=self.xticklables,
            yticklabels=self.yticklables,
            linecolor="grey",
            linewidth=0.2
        )
        if self.color_commits:
            color_map = get_author_color_map(case_study)
            commit_lookup_helper = create_commit_lookup_helper(
                case_study.project_name
            )
            for label in axis.get_yticklabels():
                commit = commit_lookup_helper(FullCommitHash(label.get_text()))
                label.set_color(color_map[commit.author.name])
            legend = []
            for author, color in color_map.items():
                legend.append(mpatches.Patch(color=color, label=author))
            plt.legend(
                handles=legend,
                bbox_to_anchor=(1.2, 1),
                loc=2,
                borderaxespad=0.
            )
        plt.setp(
            axis.get_xticklabels(), fontsize=self.plot_config.x_tick_size()
        )
        plt.setp(
            axis.get_yticklabels(), fontsize=self.plot_config.x_tick_size()
        )

    def calc_missing_revisions(
        self, boundary_gradient: float
    ) -> tp.Set[FullCommitHash]:
        """Calculate."""
        commit_map: CommitMap = get_commit_map(
            self.plot_kwargs['case_study'].project_name
        )

        def head_cm_neighbours(
            lhs_cm: ShortCommitHash, rhs_cm: ShortCommitHash
        ) -> bool:
            return commit_map.short_time_id(
                lhs_cm
            ) + 1 == commit_map.short_time_id(rhs_cm)

        new_revs: tp.Set[FullCommitHash] = set()

        data = self.data_function(self.plot_kwargs['case_study'])
        data.fillna(value=0, inplace=True)
        df_iter = data.items()
        last_revision, last_column = next(df_iter)
        for revision, column in df_iter:
            gradient = abs(column - last_column)
            if any(gradient > (boundary_gradient * 100)):
                lhs_cm = last_revision
                rhs_cm = revision
                if head_cm_neighbours(lhs_cm, rhs_cm):
                    print(
                        "Found steep gradient between neighbours " +
                        f"{lhs_cm} - {rhs_cm}: {round(max(gradient), 5)}"
                    )
                else:
                    print(
                        "Unusual gradient between " +
                        f"{lhs_cm} - {rhs_cm}: {round(max(gradient), 5)}"
                    )
                    new_rev_id = round((
                        commit_map.short_time_id(lhs_cm) +
                        commit_map.short_time_id(rhs_cm)
                    ) / 2.0)
                    new_rev = commit_map.c_hash(new_rev_id)
                    print(
                        f"-> Adding {new_rev} as new revision to the sample set"
                    )
                    new_revs.add(new_rev)
                print()
            last_revision = revision
            last_column = column
        return new_revs


class SurvivingInteractionsPlot(
    HeatMapPlot, plot_name="surviving_interactions_plot"
):
    NAME = 'surviving_interactions_plot'

    def __init__(self, plot_config: PlotConfig, **kwargs: tp.Any):
        super().__init__(
            self.NAME, plot_config, get_normalized_interactions_per_commit_wide,
            **kwargs
        )
        self.color_commits = True


class SurvivingLinesPlot(HeatMapPlot, plot_name="surviving_commit_plot"):

    def calc_missing_revisions(
        self, boundary_gradient: float
    ) -> tp.Set[FullCommitHash]:
        pass

    NAME = 'surviving_commit_plot'

    def __init__(self, plot_config: PlotConfig, **kwargs: tp.Any):
        super().__init__(
            self.NAME, plot_config, get_normalized_lines_per_commit_wide,
            **kwargs
        )
        self.color_commits = True


class CompareSurvivalPlot(HeatMapPlot, plot_name="compare_survival"):

    def calc_missing_revisions(
        self, boundary_gradient: float
    ) -> tp.Set[FullCommitHash]:
        pass

    NAME = 'compare_survival'

    def __init__(self, plot_config: PlotConfig, **kwargs: tp.Any):
        super().__init__(
            self.NAME, plot_config, lines_and_interactions, **kwargs
        )
        self.yticklables = 3
        self.color_commits = True


class SurvivingCommitPlotGenerator(
    PlotGenerator,
    generator_name="commit-survival",
    options=[REQUIRE_CASE_STUDY]
):

    def generate(self) -> tp.List['varats.plot.plot.Plot']:
        return [
            SurvivingInteractionsPlot(self.plot_config, **self.plot_kwargs),
            SurvivingLinesPlot(self.plot_config, **self.plot_kwargs),
            CompareSurvivalPlot(self.plot_config, **self.plot_kwargs)
        ]
