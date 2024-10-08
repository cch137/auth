import { load } from "cheerio";

type ParsedTable = (string | ParsedTable)[][];

interface ParseTableOptions {
  removeEmptyRow?: boolean;
  removeRepeatedNullCharacters?: boolean;
}

function htmlTableTo2DArray(
  html: string,
  options: ParseTableOptions = {}
): ParsedTable {
  const { removeEmptyRow = true, removeRepeatedNullCharacters = true } =
    options;
  const $ = load(html);
  const table = $([...$("table")][0]); // 選擇HTML中的表格元素

  const result: ParsedTable = [];

  // 遍歷每一個表格行（tr）
  const tr_list = [
    ...table.children("thead").children("tr"),
    ...table.children("tbody").children("tr"),
    ...table.children("tfoot").children("tr"),
    ...table.children("tr"),
  ];

  tr_list.forEach((rowElement) => {
    const row: (string | ParsedTable)[] = [];

    // 遍歷行中的每一個單元格（td或th）
    $(rowElement)
      .children("th, td")
      .each(function (_i, rawCellElement) {
        // 處理單元格並添加到行中
        const cellElement = $(rawCellElement);
        const tableInCell = cellElement.children("table");
        if (tableInCell.length !== 0) {
          row.push(
            [...tableInCell]
              .map((_table) => {
                let _tableHtml = ($(_table).html() || "").trim();
                if (!_tableHtml.includes("<table>"))
                  _tableHtml = `<table>${$(_table).html()}</table>`;
                return htmlTableTo2DArray(_tableHtml);
              }, options)
              .flat()
          );
          return;
        }
        // 否則，返回單元格文本
        row.push(
          removeRepeatedNullCharacters
            ? cellElement
                .text()
                .trim()
                .split("\n")
                .map((l) => l.replace(/\s+/g, " ").trim())
                .filter((l) => l)
                .join("\n")
            : cellElement.text().trim()
        );
      });

    if (
      removeEmptyRow &&
      row.map((i) => (Array.isArray(i) ? i.length : i)).filter((i) => i)
        .length === 0
    ) {
      return;
    }

    result.push(row); // 添加行到結果中
  });

  return result;
}

export type { ParsedTable, ParseTableOptions };

export default htmlTableTo2DArray;
