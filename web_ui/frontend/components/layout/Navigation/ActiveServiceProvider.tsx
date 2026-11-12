/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

'use client';

import {
  createContext,
  ReactNode,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';
import { usePathname } from 'next/navigation';

import { ServerType } from '@/index';

// Every module that owns a top-level route and a rail of its own. Typed as a
// record over ServerType so adding a module to the union fails to compile
// until it is listed here too.
const SERVICE_ROUTES: Record<ServerType, true> = {
  origin: true,
  cache: true,
  director: true,
  registry: true,
  transfer: true,
};

const isServerType = (value: unknown): value is ServerType =>
  typeof value === 'string' &&
  Object.prototype.hasOwnProperty.call(SERVICE_ROUTES, value);

// sessionStorage rather than localStorage: it is per tab, so two tabs working
// in different modules each keep their own rail, and it survives the full
// page loads that a static export makes between top-level routes.
const STORAGE_KEY = 'pelican.navigation.activeService';

const readStored = (): ServerType | undefined => {
  try {
    const value = window.sessionStorage.getItem(STORAGE_KEY);
    return isServerType(value) ? value : undefined;
  } catch {
    return undefined;
  }
};

const writeStored = (service: ServerType) => {
  try {
    window.sessionStorage.setItem(STORAGE_KEY, service);
  } catch {
    // Storage blocked (private mode, sandboxed frame): the in-memory value
    // still carries the choice for client-side navigation.
  }
};

/** The module route a pathname belongs to, if any. */
export const serviceFromPathname = (
  pathname: string | null
): ServerType | undefined => {
  const segment = pathname?.split('/').find((part) => part !== '');
  return isServerType(segment) ? segment : undefined;
};

type ActiveService = {
  /**
   * The module the caller was last working in. Server-wide pages (Settings,
   * Groups, Users, Profile) belong to no module, so they show this one's rail
   * rather than a list of every module the process runs.
   */
  service?: ServerType;
  /**
   * False until the stored value has been read. Storage is only reachable
   * after mount, and a rail rendered before then would show the fallback
   * module and then swap.
   */
  resolved: boolean;
};

const ActiveServiceContext = createContext<ActiveService>({
  resolved: false,
});

export const ActiveServiceProvider = ({
  children,
}: {
  children: ReactNode;
}) => {
  const pathname = usePathname();
  const [service, setService] = useState<ServerType | undefined>(undefined);
  const [resolved, setResolved] = useState(false);

  useEffect(() => {
    const current = serviceFromPathname(pathname);
    if (current) {
      writeStored(current);
      setService(current);
    } else {
      setService((previous) => previous ?? readStored());
    }
    setResolved(true);
  }, [pathname]);

  const value = useMemo(() => ({ service, resolved }), [service, resolved]);

  return (
    <ActiveServiceContext.Provider value={value}>
      {children}
    </ActiveServiceContext.Provider>
  );
};

export const useActiveService = () => useContext(ActiveServiceContext);
