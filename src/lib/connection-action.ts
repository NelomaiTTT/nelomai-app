export interface ConnectionActionState {
  epoch: number;
  startBusy: boolean;
  cancelBusy: boolean;
}

export interface BegunConnectionAction {
  state: ConnectionActionState;
  token: number;
}

export function initialConnectionActionState(): ConnectionActionState {
  return { epoch: 0, startBusy: false, cancelBusy: false };
}

export function canBeginConnectionAction(
  state: ConnectionActionState,
  globallyBusy: boolean,
  stopping: boolean,
): boolean {
  if (state.cancelBusy) return false;
  if (stopping && state.startBusy) return true;
  return !globallyBusy && !state.startBusy;
}

export function beginConnectionStart(
  state: ConnectionActionState,
): BegunConnectionAction {
  const epoch = state.epoch + 1;
  return {
    token: epoch,
    state: { epoch, startBusy: true, cancelBusy: state.cancelBusy },
  };
}

export function beginConnectionStop(
  state: ConnectionActionState,
): BegunConnectionAction {
  const epoch = state.epoch + 1;
  return {
    token: epoch,
    state: { epoch, startBusy: state.startBusy, cancelBusy: true },
  };
}

export function finishConnectionStart(
  state: ConnectionActionState,
): ConnectionActionState {
  return { ...state, startBusy: false };
}

export function finishConnectionStop(
  state: ConnectionActionState,
): ConnectionActionState {
  return { ...state, cancelBusy: false };
}

export function isCurrentConnectionAction(
  state: ConnectionActionState,
  token: number,
): boolean {
  return state.epoch === token;
}
