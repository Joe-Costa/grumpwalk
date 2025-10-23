#!/usr/bin/env python3
"""
Examples of querying Iceberg tables for the parquet index.

Shows three approaches:
1. PyArrow - Direct parquet file reading (what we just used)
2. PyIceberg - Using the Iceberg Python API
3. DuckDB - SQL queries over Iceberg data
"""

import sys

def example_1_pyarrow():
    """Method 1: Direct PyArrow queries on Iceberg data files"""
    print("\n" + "=" * 80)
    print("METHOD 1: PyArrow (Direct Parquet Reading)")
    print("=" * 80)
    
    import pyarrow as pa
    import pyarrow.parquet as pq
    import pyarrow.compute as pc
    import glob
    
    # Read all Iceberg data files
    data_files = glob.glob('iceberg_test_catalog/warehouse/default/fs_index/data/*.parquet')
    tables = [pq.read_table(f) for f in data_files]
    combined = pa.concat_tables(tables)
    
    print(f"Total records: {len(combined):,}")
    
    # Query: 2 newest files
    sorted_indices = pc.sort_indices(combined, sort_keys=[("modification_time", "descending")])
    top_2 = combined.take(sorted_indices[:2])
    
    print("\n2 Newest Files:")
    for i in range(len(top_2)):
        print(f"  {i+1}. {top_2['path'][i].as_py()}")
        print(f"     Modified: {top_2['modification_time'][i].as_py()}")
    
    # Query: Largest files
    print("\n2 Largest Files:")
    size_sorted = pc.sort_indices(combined, sort_keys=[("size", "descending")])
    largest_2 = combined.take(size_sorted[:2])
    
    for i in range(len(largest_2)):
        size = largest_2['size'][i].as_py()
        print(f"  {i+1}. {largest_2['path'][i].as_py()}")
        print(f"     Size: {size:,} bytes ({size / 1024 / 1024:.2f} MB)")


def example_2_pyiceberg():
    """Method 2: PyIceberg API with filtering"""
    print("\n" + "=" * 80)
    print("METHOD 2: PyIceberg API")
    print("=" * 80)
    
    from pyiceberg.catalog.sql import SqlCatalog
    import pyarrow.compute as pc
    
    # Load catalog and table
    catalog = SqlCatalog(
        "local",
        **{
            "uri": "sqlite:///iceberg_test_catalog/iceberg_catalog.db",
            "warehouse": "iceberg_test_catalog/warehouse",
        },
    )
    
    table = catalog.load_table("default.fs_index")
    
    # Scan entire table to PyArrow
    scan = table.scan()
    arrow_table = scan.to_arrow()
    
    print(f"Total records: {len(arrow_table):,}")
    print(f"Table schema has {len(arrow_table.schema)} columns")
    
    # Filter: Files larger than 10 MB
    large_files = pc.filter(
        arrow_table,
        pc.greater(arrow_table['size'], 10 * 1024 * 1024)
    )
    
    print(f"\nFiles larger than 10 MB: {len(large_files):,}")
    
    # Sort and show top 2
    if len(large_files) > 0:
        sorted_idx = pc.sort_indices(large_files, sort_keys=[("size", "descending")])
        top_large = large_files.take(sorted_idx[:min(2, len(large_files))])
        
        print("Top 2 largest files over 10 MB:")
        for i in range(len(top_large)):
            size = top_large['size'][i].as_py()
            print(f"  {i+1}. {top_large['path'][i].as_py()}")
            print(f"     Size: {size:,} bytes ({size / 1024 / 1024:.2f} MB)")


def example_3_duckdb():
    """Method 3: DuckDB SQL queries"""
    print("\n" + "=" * 80)
    print("METHOD 3: DuckDB SQL")
    print("=" * 80)
    
    import duckdb
    
    con = duckdb.connect(database=":memory:")
    
    # Read Iceberg data files directly
    data_pattern = "iceberg_test_catalog/warehouse/default/fs_index/data/*.parquet"
    
    # Query 1: 2 newest files
    print("\n2 Newest Files (SQL):")
    result = con.execute(f"""
        SELECT 
            path,
            name,
            type,
            modification_time,
            size
        FROM read_parquet('{data_pattern}')
        WHERE type = 'FS_FILE_TYPE_FILE'
        ORDER BY modification_time DESC
        LIMIT 2
    """).fetchall()
    
    for i, row in enumerate(result, 1):
        print(f"  {i}. {row[0]}")
        print(f"     Modified: {row[3]}, Size: {row[4]:,} bytes")
    
    # Query 2: Count by file type
    print("\nFile Type Distribution:")
    result = con.execute(f"""
        SELECT 
            type,
            COUNT(*) as count,
            SUM(size) as total_size
        FROM read_parquet('{data_pattern}')
        GROUP BY type
        ORDER BY count DESC
    """).fetchall()
    
    for row in result:
        print(f"  {row[0]}: {row[1]:,} files, {row[2]:,} bytes")
    
    # Query 3: Recently modified files (last 7 days)
    print("\nRecently Modified Files (last 7 days):")
    result = con.execute(f"""
        SELECT 
            path,
            modification_time,
            size
        FROM read_parquet('{data_pattern}')
        WHERE modification_time > (CURRENT_TIMESTAMP - INTERVAL '7 days')
            AND type = 'FS_FILE_TYPE_FILE'
        ORDER BY modification_time DESC
        LIMIT 5
    """).fetchall()
    
    if result:
        for i, row in enumerate(result, 1):
            print(f"  {i}. {row[0]}")
            print(f"     Modified: {row[1]}")
    else:
        print("  (No files modified in last 7 days)")
    
    con.close()


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Query Iceberg table examples")
    parser.add_argument(
        "--method",
        choices=["pyarrow", "pyiceberg", "duckdb", "all"],
        default="all",
        help="Which query method to demonstrate",
    )
    
    args = parser.parse_args()
    
    try:
        if args.method in ["pyarrow", "all"]:
            example_1_pyarrow()
        
        if args.method in ["pyiceberg", "all"]:
            example_2_pyiceberg()
        
        if args.method in ["duckdb", "all"]:
            example_3_duckdb()
            
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    print("\n" + "=" * 80)
    print("Query examples completed!")
    print("=" * 80 + "\n")
