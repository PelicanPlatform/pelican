const numberSort = (a: string, b: string) => {
  const numA = parseFloat(a);
  const numB = parseFloat(b);

  if (isNaN(numA) && isNaN(numB)) {
    return 0; // Both are not numbers, consider them equal
  } else if (isNaN(numA)) {
    return -1; // a is not a number, b is a number, b should come first
  } else if (isNaN(numB)) {
    return 1; // b is not a number, a is a number, a should come first
  } else {
    return numA - numB; // Both are numbers, sort by their numeric value
  }
};

export default numberSort;
