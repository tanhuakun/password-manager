import React from "react";
import { useTable } from "react-table";
import { PencilFill, TrashFill } from "react-bootstrap-icons";

// TODO: Make better, Currently a POC.

function Dashboard() {
  const data = React.useMemo(
    () => [
      {
        name: "google",
        password: "12345",
      },
      {
        name: "facebook",
        password: "!2345",
      },
    ],
    []
  );

  const columns = React.useMemo(
    () => [
      {
        Header: "Name",
        accessor: "name", // accessor is the "key" in the data
      },
      {
        Header: "Password",
        accessor: "password",
      },
      {
        Header: "Actions",
        Cell: ({ cell }) => (
          <div>
            <PencilFill onClick={() => console.log(cell)}></PencilFill>
            <TrashFill></TrashFill>
          </div>
        ),
      },
    ],
    []
  );

  const { getTableProps, getTableBodyProps, headerGroups, rows, prepareRow } =
    useTable({ columns, data });

  return (
    <div className="px-4">
      <h6 className="display-6">Passwords</h6>
      <table
        {...getTableProps()}
        className="w-100"
        style={{ border: "solid 1px grey" }}
      >
        <thead>
          {headerGroups.map((headerGroup) => (
            <tr {...headerGroup.getHeaderGroupProps()}>
              {headerGroup.headers.map((column) => (
                <th
                  {...column.getHeaderProps()}
                  style={{
                    border: "solid 1px grey",
                    background: "white",
                    color: "black",
                    fontWeight: "bold",
                  }}
                >
                  {column.render("Header")}
                </th>
              ))}
            </tr>
          ))}
        </thead>
        <tbody {...getTableBodyProps()}>
          {rows.map((row) => {
            prepareRow(row);
            return (
              <tr {...row.getRowProps()}>
                {row.cells.map((cell) => {
                  return (
                    <td
                      {...cell.getCellProps()}
                      style={{
                        padding: "10px",
                        border: "solid 1px gray",
                        background: "aliceblue",
                      }}
                    >
                      {cell.render("Cell")}
                    </td>
                  );
                })}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export default Dashboard;
