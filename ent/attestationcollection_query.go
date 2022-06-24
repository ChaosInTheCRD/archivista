// Code generated by entc, DO NOT EDIT.

package ent

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"math"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/testifysec/archivist/ent/attestation"
	"github.com/testifysec/archivist/ent/attestationcollection"
	"github.com/testifysec/archivist/ent/predicate"
	"github.com/testifysec/archivist/ent/statement"
)

// AttestationCollectionQuery is the builder for querying AttestationCollection entities.
type AttestationCollectionQuery struct {
	config
	limit      *int
	offset     *int
	unique     *bool
	order      []OrderFunc
	fields     []string
	predicates []predicate.AttestationCollection
	// eager-loading edges.
	withAttestations *AttestationQuery
	withStatement    *StatementQuery
	withFKs          bool
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the AttestationCollectionQuery builder.
func (acq *AttestationCollectionQuery) Where(ps ...predicate.AttestationCollection) *AttestationCollectionQuery {
	acq.predicates = append(acq.predicates, ps...)
	return acq
}

// Limit adds a limit step to the query.
func (acq *AttestationCollectionQuery) Limit(limit int) *AttestationCollectionQuery {
	acq.limit = &limit
	return acq
}

// Offset adds an offset step to the query.
func (acq *AttestationCollectionQuery) Offset(offset int) *AttestationCollectionQuery {
	acq.offset = &offset
	return acq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (acq *AttestationCollectionQuery) Unique(unique bool) *AttestationCollectionQuery {
	acq.unique = &unique
	return acq
}

// Order adds an order step to the query.
func (acq *AttestationCollectionQuery) Order(o ...OrderFunc) *AttestationCollectionQuery {
	acq.order = append(acq.order, o...)
	return acq
}

// QueryAttestations chains the current query on the "attestations" edge.
func (acq *AttestationCollectionQuery) QueryAttestations() *AttestationQuery {
	query := &AttestationQuery{config: acq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := acq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := acq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(attestationcollection.Table, attestationcollection.FieldID, selector),
			sqlgraph.To(attestation.Table, attestation.FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, attestationcollection.AttestationsTable, attestationcollection.AttestationsColumn),
		)
		fromU = sqlgraph.SetNeighbors(acq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// QueryStatement chains the current query on the "statement" edge.
func (acq *AttestationCollectionQuery) QueryStatement() *StatementQuery {
	query := &StatementQuery{config: acq.config}
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := acq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := acq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(attestationcollection.Table, attestationcollection.FieldID, selector),
			sqlgraph.To(statement.Table, statement.FieldID),
			sqlgraph.Edge(sqlgraph.O2O, true, attestationcollection.StatementTable, attestationcollection.StatementColumn),
		)
		fromU = sqlgraph.SetNeighbors(acq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first AttestationCollection entity from the query.
// Returns a *NotFoundError when no AttestationCollection was found.
func (acq *AttestationCollectionQuery) First(ctx context.Context) (*AttestationCollection, error) {
	nodes, err := acq.Limit(1).All(ctx)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{attestationcollection.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (acq *AttestationCollectionQuery) FirstX(ctx context.Context) *AttestationCollection {
	node, err := acq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first AttestationCollection ID from the query.
// Returns a *NotFoundError when no AttestationCollection ID was found.
func (acq *AttestationCollectionQuery) FirstID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = acq.Limit(1).IDs(ctx); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{attestationcollection.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (acq *AttestationCollectionQuery) FirstIDX(ctx context.Context) int {
	id, err := acq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single AttestationCollection entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one AttestationCollection entity is found.
// Returns a *NotFoundError when no AttestationCollection entities are found.
func (acq *AttestationCollectionQuery) Only(ctx context.Context) (*AttestationCollection, error) {
	nodes, err := acq.Limit(2).All(ctx)
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{attestationcollection.Label}
	default:
		return nil, &NotSingularError{attestationcollection.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (acq *AttestationCollectionQuery) OnlyX(ctx context.Context) *AttestationCollection {
	node, err := acq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only AttestationCollection ID in the query.
// Returns a *NotSingularError when more than one AttestationCollection ID is found.
// Returns a *NotFoundError when no entities are found.
func (acq *AttestationCollectionQuery) OnlyID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = acq.Limit(2).IDs(ctx); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{attestationcollection.Label}
	default:
		err = &NotSingularError{attestationcollection.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (acq *AttestationCollectionQuery) OnlyIDX(ctx context.Context) int {
	id, err := acq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of AttestationCollections.
func (acq *AttestationCollectionQuery) All(ctx context.Context) ([]*AttestationCollection, error) {
	if err := acq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	return acq.sqlAll(ctx)
}

// AllX is like All, but panics if an error occurs.
func (acq *AttestationCollectionQuery) AllX(ctx context.Context) []*AttestationCollection {
	nodes, err := acq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of AttestationCollection IDs.
func (acq *AttestationCollectionQuery) IDs(ctx context.Context) ([]int, error) {
	var ids []int
	if err := acq.Select(attestationcollection.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (acq *AttestationCollectionQuery) IDsX(ctx context.Context) []int {
	ids, err := acq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (acq *AttestationCollectionQuery) Count(ctx context.Context) (int, error) {
	if err := acq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return acq.sqlCount(ctx)
}

// CountX is like Count, but panics if an error occurs.
func (acq *AttestationCollectionQuery) CountX(ctx context.Context) int {
	count, err := acq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (acq *AttestationCollectionQuery) Exist(ctx context.Context) (bool, error) {
	if err := acq.prepareQuery(ctx); err != nil {
		return false, err
	}
	return acq.sqlExist(ctx)
}

// ExistX is like Exist, but panics if an error occurs.
func (acq *AttestationCollectionQuery) ExistX(ctx context.Context) bool {
	exist, err := acq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the AttestationCollectionQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (acq *AttestationCollectionQuery) Clone() *AttestationCollectionQuery {
	if acq == nil {
		return nil
	}
	return &AttestationCollectionQuery{
		config:           acq.config,
		limit:            acq.limit,
		offset:           acq.offset,
		order:            append([]OrderFunc{}, acq.order...),
		predicates:       append([]predicate.AttestationCollection{}, acq.predicates...),
		withAttestations: acq.withAttestations.Clone(),
		withStatement:    acq.withStatement.Clone(),
		// clone intermediate query.
		sql:    acq.sql.Clone(),
		path:   acq.path,
		unique: acq.unique,
	}
}

// WithAttestations tells the query-builder to eager-load the nodes that are connected to
// the "attestations" edge. The optional arguments are used to configure the query builder of the edge.
func (acq *AttestationCollectionQuery) WithAttestations(opts ...func(*AttestationQuery)) *AttestationCollectionQuery {
	query := &AttestationQuery{config: acq.config}
	for _, opt := range opts {
		opt(query)
	}
	acq.withAttestations = query
	return acq
}

// WithStatement tells the query-builder to eager-load the nodes that are connected to
// the "statement" edge. The optional arguments are used to configure the query builder of the edge.
func (acq *AttestationCollectionQuery) WithStatement(opts ...func(*StatementQuery)) *AttestationCollectionQuery {
	query := &StatementQuery{config: acq.config}
	for _, opt := range opts {
		opt(query)
	}
	acq.withStatement = query
	return acq
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		Name string `json:"name,omitempty"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.AttestationCollection.Query().
//		GroupBy(attestationcollection.FieldName).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
//
func (acq *AttestationCollectionQuery) GroupBy(field string, fields ...string) *AttestationCollectionGroupBy {
	group := &AttestationCollectionGroupBy{config: acq.config}
	group.fields = append([]string{field}, fields...)
	group.path = func(ctx context.Context) (prev *sql.Selector, err error) {
		if err := acq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		return acq.sqlQuery(ctx), nil
	}
	return group
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		Name string `json:"name,omitempty"`
//	}
//
//	client.AttestationCollection.Query().
//		Select(attestationcollection.FieldName).
//		Scan(ctx, &v)
//
func (acq *AttestationCollectionQuery) Select(fields ...string) *AttestationCollectionSelect {
	acq.fields = append(acq.fields, fields...)
	return &AttestationCollectionSelect{AttestationCollectionQuery: acq}
}

func (acq *AttestationCollectionQuery) prepareQuery(ctx context.Context) error {
	for _, f := range acq.fields {
		if !attestationcollection.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if acq.path != nil {
		prev, err := acq.path(ctx)
		if err != nil {
			return err
		}
		acq.sql = prev
	}
	return nil
}

func (acq *AttestationCollectionQuery) sqlAll(ctx context.Context) ([]*AttestationCollection, error) {
	var (
		nodes       = []*AttestationCollection{}
		withFKs     = acq.withFKs
		_spec       = acq.querySpec()
		loadedTypes = [2]bool{
			acq.withAttestations != nil,
			acq.withStatement != nil,
		}
	)
	if acq.withStatement != nil {
		withFKs = true
	}
	if withFKs {
		_spec.Node.Columns = append(_spec.Node.Columns, attestationcollection.ForeignKeys...)
	}
	_spec.ScanValues = func(columns []string) ([]interface{}, error) {
		node := &AttestationCollection{config: acq.config}
		nodes = append(nodes, node)
		return node.scanValues(columns)
	}
	_spec.Assign = func(columns []string, values []interface{}) error {
		if len(nodes) == 0 {
			return fmt.Errorf("ent: Assign called without calling ScanValues")
		}
		node := nodes[len(nodes)-1]
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	if err := sqlgraph.QueryNodes(ctx, acq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}

	if query := acq.withAttestations; query != nil {
		fks := make([]driver.Value, 0, len(nodes))
		nodeids := make(map[int]*AttestationCollection)
		for i := range nodes {
			fks = append(fks, nodes[i].ID)
			nodeids[nodes[i].ID] = nodes[i]
			nodes[i].Edges.Attestations = []*Attestation{}
		}
		query.withFKs = true
		query.Where(predicate.Attestation(func(s *sql.Selector) {
			s.Where(sql.InValues(attestationcollection.AttestationsColumn, fks...))
		}))
		neighbors, err := query.All(ctx)
		if err != nil {
			return nil, err
		}
		for _, n := range neighbors {
			fk := n.attestation_collection_attestations
			if fk == nil {
				return nil, fmt.Errorf(`foreign-key "attestation_collection_attestations" is nil for node %v`, n.ID)
			}
			node, ok := nodeids[*fk]
			if !ok {
				return nil, fmt.Errorf(`unexpected foreign-key "attestation_collection_attestations" returned %v for node %v`, *fk, n.ID)
			}
			node.Edges.Attestations = append(node.Edges.Attestations, n)
		}
	}

	if query := acq.withStatement; query != nil {
		ids := make([]int, 0, len(nodes))
		nodeids := make(map[int][]*AttestationCollection)
		for i := range nodes {
			if nodes[i].statement_attestation_collections == nil {
				continue
			}
			fk := *nodes[i].statement_attestation_collections
			if _, ok := nodeids[fk]; !ok {
				ids = append(ids, fk)
			}
			nodeids[fk] = append(nodeids[fk], nodes[i])
		}
		query.Where(statement.IDIn(ids...))
		neighbors, err := query.All(ctx)
		if err != nil {
			return nil, err
		}
		for _, n := range neighbors {
			nodes, ok := nodeids[n.ID]
			if !ok {
				return nil, fmt.Errorf(`unexpected foreign-key "statement_attestation_collections" returned %v`, n.ID)
			}
			for i := range nodes {
				nodes[i].Edges.Statement = n
			}
		}
	}

	return nodes, nil
}

func (acq *AttestationCollectionQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := acq.querySpec()
	_spec.Node.Columns = acq.fields
	if len(acq.fields) > 0 {
		_spec.Unique = acq.unique != nil && *acq.unique
	}
	return sqlgraph.CountNodes(ctx, acq.driver, _spec)
}

func (acq *AttestationCollectionQuery) sqlExist(ctx context.Context) (bool, error) {
	n, err := acq.sqlCount(ctx)
	if err != nil {
		return false, fmt.Errorf("ent: check existence: %w", err)
	}
	return n > 0, nil
}

func (acq *AttestationCollectionQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := &sqlgraph.QuerySpec{
		Node: &sqlgraph.NodeSpec{
			Table:   attestationcollection.Table,
			Columns: attestationcollection.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: attestationcollection.FieldID,
			},
		},
		From:   acq.sql,
		Unique: true,
	}
	if unique := acq.unique; unique != nil {
		_spec.Unique = *unique
	}
	if fields := acq.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, attestationcollection.FieldID)
		for i := range fields {
			if fields[i] != attestationcollection.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := acq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := acq.limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := acq.offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := acq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (acq *AttestationCollectionQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(acq.driver.Dialect())
	t1 := builder.Table(attestationcollection.Table)
	columns := acq.fields
	if len(columns) == 0 {
		columns = attestationcollection.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if acq.sql != nil {
		selector = acq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if acq.unique != nil && *acq.unique {
		selector.Distinct()
	}
	for _, p := range acq.predicates {
		p(selector)
	}
	for _, p := range acq.order {
		p(selector)
	}
	if offset := acq.offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := acq.limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// AttestationCollectionGroupBy is the group-by builder for AttestationCollection entities.
type AttestationCollectionGroupBy struct {
	config
	fields []string
	fns    []AggregateFunc
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Aggregate adds the given aggregation functions to the group-by query.
func (acgb *AttestationCollectionGroupBy) Aggregate(fns ...AggregateFunc) *AttestationCollectionGroupBy {
	acgb.fns = append(acgb.fns, fns...)
	return acgb
}

// Scan applies the group-by query and scans the result into the given value.
func (acgb *AttestationCollectionGroupBy) Scan(ctx context.Context, v interface{}) error {
	query, err := acgb.path(ctx)
	if err != nil {
		return err
	}
	acgb.sql = query
	return acgb.sqlScan(ctx, v)
}

// ScanX is like Scan, but panics if an error occurs.
func (acgb *AttestationCollectionGroupBy) ScanX(ctx context.Context, v interface{}) {
	if err := acgb.Scan(ctx, v); err != nil {
		panic(err)
	}
}

// Strings returns list of strings from group-by.
// It is only allowed when executing a group-by query with one field.
func (acgb *AttestationCollectionGroupBy) Strings(ctx context.Context) ([]string, error) {
	if len(acgb.fields) > 1 {
		return nil, errors.New("ent: AttestationCollectionGroupBy.Strings is not achievable when grouping more than 1 field")
	}
	var v []string
	if err := acgb.Scan(ctx, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// StringsX is like Strings, but panics if an error occurs.
func (acgb *AttestationCollectionGroupBy) StringsX(ctx context.Context) []string {
	v, err := acgb.Strings(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// String returns a single string from a group-by query.
// It is only allowed when executing a group-by query with one field.
func (acgb *AttestationCollectionGroupBy) String(ctx context.Context) (_ string, err error) {
	var v []string
	if v, err = acgb.Strings(ctx); err != nil {
		return
	}
	switch len(v) {
	case 1:
		return v[0], nil
	case 0:
		err = &NotFoundError{attestationcollection.Label}
	default:
		err = fmt.Errorf("ent: AttestationCollectionGroupBy.Strings returned %d results when one was expected", len(v))
	}
	return
}

// StringX is like String, but panics if an error occurs.
func (acgb *AttestationCollectionGroupBy) StringX(ctx context.Context) string {
	v, err := acgb.String(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Ints returns list of ints from group-by.
// It is only allowed when executing a group-by query with one field.
func (acgb *AttestationCollectionGroupBy) Ints(ctx context.Context) ([]int, error) {
	if len(acgb.fields) > 1 {
		return nil, errors.New("ent: AttestationCollectionGroupBy.Ints is not achievable when grouping more than 1 field")
	}
	var v []int
	if err := acgb.Scan(ctx, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// IntsX is like Ints, but panics if an error occurs.
func (acgb *AttestationCollectionGroupBy) IntsX(ctx context.Context) []int {
	v, err := acgb.Ints(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Int returns a single int from a group-by query.
// It is only allowed when executing a group-by query with one field.
func (acgb *AttestationCollectionGroupBy) Int(ctx context.Context) (_ int, err error) {
	var v []int
	if v, err = acgb.Ints(ctx); err != nil {
		return
	}
	switch len(v) {
	case 1:
		return v[0], nil
	case 0:
		err = &NotFoundError{attestationcollection.Label}
	default:
		err = fmt.Errorf("ent: AttestationCollectionGroupBy.Ints returned %d results when one was expected", len(v))
	}
	return
}

// IntX is like Int, but panics if an error occurs.
func (acgb *AttestationCollectionGroupBy) IntX(ctx context.Context) int {
	v, err := acgb.Int(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Float64s returns list of float64s from group-by.
// It is only allowed when executing a group-by query with one field.
func (acgb *AttestationCollectionGroupBy) Float64s(ctx context.Context) ([]float64, error) {
	if len(acgb.fields) > 1 {
		return nil, errors.New("ent: AttestationCollectionGroupBy.Float64s is not achievable when grouping more than 1 field")
	}
	var v []float64
	if err := acgb.Scan(ctx, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// Float64sX is like Float64s, but panics if an error occurs.
func (acgb *AttestationCollectionGroupBy) Float64sX(ctx context.Context) []float64 {
	v, err := acgb.Float64s(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Float64 returns a single float64 from a group-by query.
// It is only allowed when executing a group-by query with one field.
func (acgb *AttestationCollectionGroupBy) Float64(ctx context.Context) (_ float64, err error) {
	var v []float64
	if v, err = acgb.Float64s(ctx); err != nil {
		return
	}
	switch len(v) {
	case 1:
		return v[0], nil
	case 0:
		err = &NotFoundError{attestationcollection.Label}
	default:
		err = fmt.Errorf("ent: AttestationCollectionGroupBy.Float64s returned %d results when one was expected", len(v))
	}
	return
}

// Float64X is like Float64, but panics if an error occurs.
func (acgb *AttestationCollectionGroupBy) Float64X(ctx context.Context) float64 {
	v, err := acgb.Float64(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Bools returns list of bools from group-by.
// It is only allowed when executing a group-by query with one field.
func (acgb *AttestationCollectionGroupBy) Bools(ctx context.Context) ([]bool, error) {
	if len(acgb.fields) > 1 {
		return nil, errors.New("ent: AttestationCollectionGroupBy.Bools is not achievable when grouping more than 1 field")
	}
	var v []bool
	if err := acgb.Scan(ctx, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// BoolsX is like Bools, but panics if an error occurs.
func (acgb *AttestationCollectionGroupBy) BoolsX(ctx context.Context) []bool {
	v, err := acgb.Bools(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Bool returns a single bool from a group-by query.
// It is only allowed when executing a group-by query with one field.
func (acgb *AttestationCollectionGroupBy) Bool(ctx context.Context) (_ bool, err error) {
	var v []bool
	if v, err = acgb.Bools(ctx); err != nil {
		return
	}
	switch len(v) {
	case 1:
		return v[0], nil
	case 0:
		err = &NotFoundError{attestationcollection.Label}
	default:
		err = fmt.Errorf("ent: AttestationCollectionGroupBy.Bools returned %d results when one was expected", len(v))
	}
	return
}

// BoolX is like Bool, but panics if an error occurs.
func (acgb *AttestationCollectionGroupBy) BoolX(ctx context.Context) bool {
	v, err := acgb.Bool(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

func (acgb *AttestationCollectionGroupBy) sqlScan(ctx context.Context, v interface{}) error {
	for _, f := range acgb.fields {
		if !attestationcollection.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("invalid field %q for group-by", f)}
		}
	}
	selector := acgb.sqlQuery()
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := acgb.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

func (acgb *AttestationCollectionGroupBy) sqlQuery() *sql.Selector {
	selector := acgb.sql.Select()
	aggregation := make([]string, 0, len(acgb.fns))
	for _, fn := range acgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	// If no columns were selected in a custom aggregation function, the default
	// selection is the fields used for "group-by", and the aggregation functions.
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(acgb.fields)+len(acgb.fns))
		for _, f := range acgb.fields {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	return selector.GroupBy(selector.Columns(acgb.fields...)...)
}

// AttestationCollectionSelect is the builder for selecting fields of AttestationCollection entities.
type AttestationCollectionSelect struct {
	*AttestationCollectionQuery
	// intermediate query (i.e. traversal path).
	sql *sql.Selector
}

// Scan applies the selector query and scans the result into the given value.
func (acs *AttestationCollectionSelect) Scan(ctx context.Context, v interface{}) error {
	if err := acs.prepareQuery(ctx); err != nil {
		return err
	}
	acs.sql = acs.AttestationCollectionQuery.sqlQuery(ctx)
	return acs.sqlScan(ctx, v)
}

// ScanX is like Scan, but panics if an error occurs.
func (acs *AttestationCollectionSelect) ScanX(ctx context.Context, v interface{}) {
	if err := acs.Scan(ctx, v); err != nil {
		panic(err)
	}
}

// Strings returns list of strings from a selector. It is only allowed when selecting one field.
func (acs *AttestationCollectionSelect) Strings(ctx context.Context) ([]string, error) {
	if len(acs.fields) > 1 {
		return nil, errors.New("ent: AttestationCollectionSelect.Strings is not achievable when selecting more than 1 field")
	}
	var v []string
	if err := acs.Scan(ctx, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// StringsX is like Strings, but panics if an error occurs.
func (acs *AttestationCollectionSelect) StringsX(ctx context.Context) []string {
	v, err := acs.Strings(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// String returns a single string from a selector. It is only allowed when selecting one field.
func (acs *AttestationCollectionSelect) String(ctx context.Context) (_ string, err error) {
	var v []string
	if v, err = acs.Strings(ctx); err != nil {
		return
	}
	switch len(v) {
	case 1:
		return v[0], nil
	case 0:
		err = &NotFoundError{attestationcollection.Label}
	default:
		err = fmt.Errorf("ent: AttestationCollectionSelect.Strings returned %d results when one was expected", len(v))
	}
	return
}

// StringX is like String, but panics if an error occurs.
func (acs *AttestationCollectionSelect) StringX(ctx context.Context) string {
	v, err := acs.String(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Ints returns list of ints from a selector. It is only allowed when selecting one field.
func (acs *AttestationCollectionSelect) Ints(ctx context.Context) ([]int, error) {
	if len(acs.fields) > 1 {
		return nil, errors.New("ent: AttestationCollectionSelect.Ints is not achievable when selecting more than 1 field")
	}
	var v []int
	if err := acs.Scan(ctx, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// IntsX is like Ints, but panics if an error occurs.
func (acs *AttestationCollectionSelect) IntsX(ctx context.Context) []int {
	v, err := acs.Ints(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Int returns a single int from a selector. It is only allowed when selecting one field.
func (acs *AttestationCollectionSelect) Int(ctx context.Context) (_ int, err error) {
	var v []int
	if v, err = acs.Ints(ctx); err != nil {
		return
	}
	switch len(v) {
	case 1:
		return v[0], nil
	case 0:
		err = &NotFoundError{attestationcollection.Label}
	default:
		err = fmt.Errorf("ent: AttestationCollectionSelect.Ints returned %d results when one was expected", len(v))
	}
	return
}

// IntX is like Int, but panics if an error occurs.
func (acs *AttestationCollectionSelect) IntX(ctx context.Context) int {
	v, err := acs.Int(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Float64s returns list of float64s from a selector. It is only allowed when selecting one field.
func (acs *AttestationCollectionSelect) Float64s(ctx context.Context) ([]float64, error) {
	if len(acs.fields) > 1 {
		return nil, errors.New("ent: AttestationCollectionSelect.Float64s is not achievable when selecting more than 1 field")
	}
	var v []float64
	if err := acs.Scan(ctx, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// Float64sX is like Float64s, but panics if an error occurs.
func (acs *AttestationCollectionSelect) Float64sX(ctx context.Context) []float64 {
	v, err := acs.Float64s(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Float64 returns a single float64 from a selector. It is only allowed when selecting one field.
func (acs *AttestationCollectionSelect) Float64(ctx context.Context) (_ float64, err error) {
	var v []float64
	if v, err = acs.Float64s(ctx); err != nil {
		return
	}
	switch len(v) {
	case 1:
		return v[0], nil
	case 0:
		err = &NotFoundError{attestationcollection.Label}
	default:
		err = fmt.Errorf("ent: AttestationCollectionSelect.Float64s returned %d results when one was expected", len(v))
	}
	return
}

// Float64X is like Float64, but panics if an error occurs.
func (acs *AttestationCollectionSelect) Float64X(ctx context.Context) float64 {
	v, err := acs.Float64(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Bools returns list of bools from a selector. It is only allowed when selecting one field.
func (acs *AttestationCollectionSelect) Bools(ctx context.Context) ([]bool, error) {
	if len(acs.fields) > 1 {
		return nil, errors.New("ent: AttestationCollectionSelect.Bools is not achievable when selecting more than 1 field")
	}
	var v []bool
	if err := acs.Scan(ctx, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// BoolsX is like Bools, but panics if an error occurs.
func (acs *AttestationCollectionSelect) BoolsX(ctx context.Context) []bool {
	v, err := acs.Bools(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Bool returns a single bool from a selector. It is only allowed when selecting one field.
func (acs *AttestationCollectionSelect) Bool(ctx context.Context) (_ bool, err error) {
	var v []bool
	if v, err = acs.Bools(ctx); err != nil {
		return
	}
	switch len(v) {
	case 1:
		return v[0], nil
	case 0:
		err = &NotFoundError{attestationcollection.Label}
	default:
		err = fmt.Errorf("ent: AttestationCollectionSelect.Bools returned %d results when one was expected", len(v))
	}
	return
}

// BoolX is like Bool, but panics if an error occurs.
func (acs *AttestationCollectionSelect) BoolX(ctx context.Context) bool {
	v, err := acs.Bool(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

func (acs *AttestationCollectionSelect) sqlScan(ctx context.Context, v interface{}) error {
	rows := &sql.Rows{}
	query, args := acs.sql.Query()
	if err := acs.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
