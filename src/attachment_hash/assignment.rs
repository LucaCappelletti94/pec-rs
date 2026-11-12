//! Complete receipt assignments and their observable uniqueness.

use super::{Attachment, Candidate, Pair};
use crate::Error;

/// A lexicographically ordered assignment cost.
type Cost = [i64; 3];

/// The paired and carried counts of an identical-candidate group.
type Observation = [i64; 2];

/// The best evidence between one sent attachment and one receipt candidate.
#[derive(Clone, Copy)]
struct Evidence {
    /// The priority level, with zero denoting incompatibility.
    level: u8,
    /// Whether generated evidence attains this level.
    generated: bool,
    /// Whether carried evidence attains this level.
    carried: bool,
}

impl Evidence {
    /// Retains every interpretation at the strongest available level.
    fn new(sent: &Attachment<'_>, candidate: &Candidate<'_>) -> Self {
        let carried = level(
            sent.name.is_some() && sent.name == candidate.file,
            sent.sha1 == candidate.sha1,
        );
        let generated = level(
            sent.name.is_some() && sent.name == candidate.hash_name(),
            candidate.hash.is_some_and(|hash| sent.has(&hash)),
        );
        let level = carried.max(generated);
        Self {
            level,
            generated: level != 0 && generated == level,
            carried: level != 0 && carried == level,
        }
    }

    /// Returns the check outcome for an available interpretation.
    const fn outcome(self, carried: bool) -> Outcome {
        if self.level == 2 {
            Outcome::Differs
        } else if carried {
            Outcome::Carried
        } else {
            Outcome::Matches
        }
    }
}

/// Ranks filename and content evidence.
const fn level(named: bool, equal: bool) -> u8 {
    match (named, equal) {
        (true, true) => 3,
        (true, false) => 2,
        (false, true) => 1,
        (false, false) => 0,
    }
}

/// The observable result for one sent attachment.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// No receipt candidate is assigned.
    Missing,
    /// A generated digest matches.
    Matches,
    /// Carried content matches.
    Carried,
    /// The filename matches and the content differs.
    Differs,
}

/// Cached receipt evidence with implicit zero-cost missing columns.
struct Matrix {
    /// Evidence in sent-major order.
    evidence: Vec<Evidence>,
    /// The number of sent attachments.
    rows: usize,
    /// The number of actual receipt candidates.
    receipts: usize,
}

impl Matrix {
    /// Evaluates both interpretations of every possible receipt pair.
    fn new(outgoing: &[Attachment<'_>], candidates: &[Candidate<'_>]) -> Self {
        let evidence = outgoing
            .iter()
            .flat_map(|sent| {
                candidates
                    .iter()
                    .map(move |candidate| Evidence::new(sent, candidate))
            })
            .collect();
        Self {
            evidence,
            rows: outgoing.len(),
            receipts: candidates.len(),
        }
    }

    /// Returns the cached evidence for a real receipt column.
    fn at(&self, row: usize, column: usize) -> Evidence {
        self.evidence[row * self.receipts + column]
    }

    /// Returns a feasible edge's lexicographic cost.
    fn cost(&self, row: usize, column: usize) -> Option<Cost> {
        if column >= self.receipts {
            return Some([0; 3]);
        }
        match self.at(row, column).level {
            3 => Some([-1, 0, 0]),
            2 => Some([0, -1, 0]),
            1 => Some([0, 0, -1]),
            _ => None,
        }
    }

    /// Returns the outcome of the chosen interpretation.
    fn outcome(&self, row: usize, column: usize) -> Outcome {
        if column >= self.receipts {
            Outcome::Missing
        } else {
            let evidence = self.at(row, column);
            evidence.outcome(!evidence.generated)
        }
    }
}

/// A minimum-cost assignment and its dual certificate.
struct Matching {
    /// The selected zero-based column for each row.
    columns: Vec<usize>,
    /// One-based column owners, with zero marking an unused column.
    owners: Vec<usize>,
    /// One-based row potentials.
    row_cost: Vec<Cost>,
    /// One-based column potentials.
    column_cost: Vec<Cost>,
}

/// Adds signed components without scalar priority multipliers.
fn add<const N: usize>(left: [i64; N], right: [i64; N]) -> [i64; N] {
    core::array::from_fn(|index| left[index] + right[index])
}

/// Subtracts signed components without scalar priority multipliers.
fn subtract<const N: usize>(left: [i64; N], right: [i64; N]) -> [i64; N] {
    core::array::from_fn(|index| left[index] - right[index])
}

impl Matching {
    /// Finds an optimal rectangular assignment with Hungarian augmenting paths.
    fn new(matrix: &Matrix) -> Self {
        let width = matrix.receipts + matrix.rows + 1;
        let mut matching = Self {
            columns: vec![0; matrix.rows],
            owners: vec![0; width],
            row_cost: vec![[0; 3]; matrix.rows + 1],
            column_cost: vec![[0; 3]; width],
        };
        let mut distances = vec![None; width];
        let mut previous = vec![0; width];
        let mut used = vec![false; width];
        for row in 1..=matrix.rows {
            matching.owners[0] = row;
            distances.fill(None);
            used.fill(false);
            let mut column = 0;
            loop {
                used[column] = true;
                let owner = matching.owners[column];
                let mut next = 0;
                let mut delta = None;
                for (candidate, &visited) in used.iter().enumerate().skip(1) {
                    if visited {
                        continue;
                    }
                    if let Some(cost) = matrix.cost(owner - 1, candidate - 1) {
                        let reduced = subtract(
                            subtract(cost, matching.row_cost[owner]),
                            matching.column_cost[candidate],
                        );
                        if distances[candidate].is_none_or(|distance| reduced < distance) {
                            distances[candidate] = Some(reduced);
                            previous[candidate] = column;
                        }
                    }
                    if let Some(distance) = distances[candidate]
                        && delta.is_none_or(|best| distance < best)
                    {
                        delta = Some(distance);
                        next = candidate;
                    }
                }
                // A free missing column always completes the augmenting path.
                let Some(delta) = delta else {
                    unreachable!("missing columns make every row assignable")
                };
                for (candidate, &visited) in used.iter().enumerate() {
                    if visited {
                        let owner = matching.owners[candidate];
                        matching.row_cost[owner] = add(matching.row_cost[owner], delta);
                        matching.column_cost[candidate] =
                            subtract(matching.column_cost[candidate], delta);
                    } else if let Some(distance) = &mut distances[candidate] {
                        *distance = subtract(*distance, delta);
                    }
                }
                column = next;
                if matching.owners[column] == 0 {
                    break;
                }
            }
            while column != 0 {
                let predecessor = previous[column];
                matching.owners[column] = matching.owners[predecessor];
                column = predecessor;
            }
        }
        for (column, &owner) in matching.owners.iter().enumerate().skip(1) {
            if owner != 0 {
                matching.columns[owner - 1] = column - 1;
            }
        }
        matching
    }
}

/// Identical candidates and their unpaired interpretations.
struct Groups {
    /// Candidate indices sorted by identity and then receipt order.
    members: Vec<usize>,
    /// Group boundaries in `members`.
    offsets: Vec<usize>,
    /// The group containing each candidate.
    indices: Vec<usize>,
    /// Whether unpaired members of each group represent carried files.
    carried: Vec<bool>,
}

impl Groups {
    /// Groups full filenames, content digests and parsed generated digests.
    fn new(outgoing: &[Attachment<'_>], candidates: &[Candidate<'_>]) -> Self {
        let mut members: Vec<_> = (0..candidates.len()).collect();
        members.sort_unstable_by(|&left, &right| {
            let a = &candidates[left];
            let b = &candidates[right];
            (a.file, &a.sha1, &a.hash, left).cmp(&(b.file, &b.sha1, &b.hash, right))
        });
        let mut offsets = Vec::new();
        let mut indices = vec![0; candidates.len()];
        let mut carried = Vec::new();
        for (position, &index) in members.iter().enumerate() {
            let candidate = &candidates[index];
            if position == 0 || {
                let previous = &candidates[members[position - 1]];
                (candidate.file, &candidate.sha1, &candidate.hash)
                    != (previous.file, &previous.sha1, &previous.hash)
            } {
                offsets.push(position);
                carried.push(
                    candidate.hash_name().is_none()
                        || outgoing
                            .iter()
                            .any(|sent| sent.name.is_some() && sent.name == candidate.file),
                );
            }
            indices[index] = carried.len() - 1;
        }
        offsets.push(members.len());
        Self {
            members,
            offsets,
            indices,
            carried,
        }
    }
}

/// A tight reassignment of one column to a row or to the free vertex.
struct Transition {
    /// The row losing this column, or the free vertex.
    to: usize,
    /// The new sent outcome, unused for transitions from the free vertex.
    outcome: Outcome,
    /// The affected receipt group, absent for missing columns.
    group: Option<usize>,
    /// The change in the group's paired and carried counts.
    delta: Observation,
}

impl Transition {
    /// Records the observation difference from the chosen column assignment.
    fn new(
        column: usize,
        carried: Option<bool>,
        outcome: Outcome,
        matrix: &Matrix,
        matching: &Matching,
        groups: &Groups,
    ) -> Self {
        let owner = matching.owners[column + 1];
        let to = owner.checked_sub(1).unwrap_or(matrix.rows);
        let group = groups.indices.get(column).copied();
        let delta = group.map_or([0; 2], |group| {
            let old_carried = if owner == 0 {
                groups.carried[group]
            } else {
                !matrix.at(owner - 1, column).generated
            };
            [
                i64::from(carried.is_some()) - i64::from(owner != 0),
                i64::from(carried.unwrap_or(groups.carried[group])) - i64::from(old_carried),
            ]
        });
        Self {
            to,
            outcome,
            group,
            delta,
        }
    }
}

/// A compact tight residual graph, including one free-column vertex.
struct Graph {
    /// Outgoing transitions grouped by source vertex.
    edges: Vec<Transition>,
    /// Vertex boundaries in `edges`.
    offsets: Vec<usize>,
}

impl Graph {
    /// Includes all tight interpretations and zero-potential dummy-row transitions.
    fn new(matrix: &Matrix, matching: &Matching, groups: &Groups) -> Self {
        let mut edges = Vec::new();
        let mut offsets = Vec::with_capacity(matrix.rows + 2);
        offsets.push(0);
        for row in 0..matrix.rows {
            for column in 0..matrix.receipts + matrix.rows {
                let Some(cost) = matrix.cost(row, column) else {
                    continue;
                };
                if cost != add(matching.row_cost[row + 1], matching.column_cost[column + 1]) {
                    continue;
                }
                if column >= matrix.receipts {
                    edges.push(Transition::new(
                        column,
                        None,
                        Outcome::Missing,
                        matrix,
                        matching,
                        groups,
                    ));
                } else {
                    let evidence = matrix.at(row, column);
                    for (carried, available) in
                        [(false, evidence.generated), (true, evidence.carried)]
                    {
                        if available {
                            edges.push(Transition::new(
                                column,
                                Some(carried),
                                evidence.outcome(carried),
                                matrix,
                                matching,
                                groups,
                            ));
                        }
                    }
                }
            }
            offsets.push(edges.len());
        }
        for column in 0..matrix.receipts + matrix.rows {
            if matching.owners[column + 1] != 0 && matching.column_cost[column + 1] == [0; 3] {
                edges.push(Transition::new(
                    column,
                    None,
                    Outcome::Missing,
                    matrix,
                    matching,
                    groups,
                ));
            }
        }
        offsets.push(edges.len());
        Self { edges, offsets }
    }

    /// Returns a vertex's outgoing transitions.
    fn outgoing(&self, vertex: usize) -> &[Transition] {
        &self.edges[self.offsets[vertex]..self.offsets[vertex + 1]]
    }

    /// Computes strongly connected components with iterative Kosaraju traversals.
    fn components(&self) -> Vec<usize> {
        let vertices = self.offsets.len() - 1;
        let mut visited = vec![false; vertices];
        let mut order = Vec::with_capacity(vertices);
        let mut frames = Vec::with_capacity(vertices);
        for root in 0..vertices {
            if visited[root] {
                continue;
            }
            visited[root] = true;
            frames.push((root, self.offsets[root]));
            while let Some((vertex, next)) = frames.last_mut() {
                if *next == self.offsets[*vertex + 1] {
                    order.push(*vertex);
                    frames.pop();
                } else {
                    let to = self.edges[*next].to;
                    *next += 1;
                    if !visited[to] {
                        visited[to] = true;
                        frames.push((to, self.offsets[to]));
                    }
                }
            }
        }
        let mut offsets = vec![0; vertices + 1];
        for edge in &self.edges {
            offsets[edge.to + 1] += 1;
        }
        let mut total = 0;
        for count in &mut offsets {
            total += *count;
            *count = total;
        }
        let mut cursors = offsets[..vertices].to_vec();
        let mut reversed = vec![0; self.edges.len()];
        for vertex in 0..vertices {
            for edge in self.outgoing(vertex) {
                reversed[cursors[edge.to]] = vertex;
                cursors[edge.to] += 1;
            }
        }
        let mut components = vec![usize::MAX; vertices];
        let mut stack = Vec::with_capacity(vertices);
        for root in order.into_iter().rev() {
            if components[root] != usize::MAX {
                continue;
            }
            components[root] = root;
            stack.push(root);
            while let Some(vertex) = stack.pop() {
                for &to in &reversed[offsets[vertex]..offsets[vertex + 1]] {
                    if components[to] == usize::MAX {
                        components[to] = root;
                        stack.push(to);
                    }
                }
            }
        }
        components
    }

    /// Rejects optimal alternatives that change a sent outcome or group observation.
    fn require_unique(
        &self,
        matrix: &Matrix,
        matching: &Matching,
        group_count: usize,
    ) -> Result<(), Error> {
        let components = self.components();
        let mut changing = vec![false; group_count];
        for (vertex, &component) in components.iter().enumerate() {
            for edge in self.outgoing(vertex) {
                if components[edge.to] != component {
                    continue;
                }
                if vertex < matrix.rows
                    && edge.outcome != matrix.outcome(vertex, matching.columns[vertex])
                {
                    return Err(Error::AmbiguousAttachments);
                }
                if let Some(group) = edge.group
                    && edge.delta != [0; 2]
                {
                    changing[group] = true;
                }
            }
        }
        let mut potentials = vec![None; components.len()];
        let mut stack = Vec::with_capacity(components.len());
        for (group, changes) in changing.into_iter().enumerate() {
            if !changes {
                continue;
            }
            potentials.fill(None);
            for root in 0..components.len() {
                if potentials[root].is_some() {
                    continue;
                }
                potentials[root] = Some([0; 2]);
                stack.push((root, [0; 2]));
                while let Some((vertex, potential)) = stack.pop() {
                    for edge in self.outgoing(vertex) {
                        if components[vertex] != components[edge.to] {
                            continue;
                        }
                        let delta = if edge.group == Some(group) {
                            edge.delta
                        } else {
                            [0; 2]
                        };
                        let implied = add(potential, delta);
                        if let Some(existing) = potentials[edge.to] {
                            if existing != implied {
                                return Err(Error::AmbiguousAttachments);
                            }
                        } else {
                            potentials[edge.to] = Some(implied);
                            stack.push((edge.to, implied));
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

/// Assigns receipt candidates only when every optimal interpretation agrees observably.
pub(super) fn assign<'s>(
    outgoing: &[Attachment<'s>],
    candidates: &mut [Candidate<'_>],
) -> Result<Vec<Option<Pair<'s>>>, Error> {
    if candidates.is_empty() {
        return Ok(vec![None; outgoing.len()]);
    }
    if outgoing.is_empty() {
        for candidate in candidates {
            candidate.paired = false;
            candidate.carried = candidate.hash_name().is_none();
        }
        return Ok(Vec::new());
    }
    let matrix = Matrix::new(outgoing, candidates);
    let matching = Matching::new(&matrix);
    let groups = Groups::new(outgoing, candidates);
    Graph::new(&matrix, &matching, &groups).require_unique(
        &matrix,
        &matching,
        groups.carried.len(),
    )?;

    let mut cursors: Vec<_> = groups.offsets[..groups.carried.len()]
        .iter()
        .map(|&start| [start; 2])
        .collect();
    for (row, &column) in matching.columns.iter().enumerate() {
        if column < matrix.receipts && matrix.at(row, column).generated {
            cursors[groups.indices[column]][1] += 1;
        }
    }
    for (index, candidate) in candidates.iter_mut().enumerate() {
        candidate.paired = false;
        candidate.carried = groups.carried[groups.indices[index]];
    }
    let mut pairs = Vec::with_capacity(outgoing.len());
    for (row, &column) in matching.columns.iter().enumerate() {
        if column >= matrix.receipts {
            pairs.push(None);
            continue;
        }
        let evidence = matrix.at(row, column);
        let carried = !evidence.generated;
        let cursor = &mut cursors[groups.indices[column]][usize::from(carried)];
        let candidate = groups.members[*cursor];
        *cursor += 1;
        candidates[candidate].paired = true;
        candidates[candidate].carried = carried;
        pairs.push(Some(Pair {
            candidate,
            changed_name: outgoing[row].name.filter(|_| evidence.level == 2),
        }));
    }
    Ok(pairs)
}
