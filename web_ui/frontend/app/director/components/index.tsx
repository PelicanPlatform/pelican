import { StringTree } from '@/index';

export * from './DirectorCard';
export * from './DirectorCardList';
export * from './NamespaceCard';

export const directoryListToTree = (directoryList: string[]): StringTree => {
  let tree = {};
  directoryList.forEach((directory) => {
    const path = directory
      .split('/')
      .filter((x) => x != '')
      .map((x) => '/' + x);
    tree = directoryListToTreeHelper(path, tree);
  });

  return tree;
};

export const directoryListToTreeHelper = (
  path: string[],
  tree: StringTree
): true | StringTree => {
  if (path.length == 0) {
    return true;
  }

  if (!tree[path[0]] || tree[path[0]] === true) {
    tree[path[0]] = {};
  }

  tree[path[0]] = directoryListToTreeHelper(path.slice(1), tree[path[0]]);

  return tree;
};
