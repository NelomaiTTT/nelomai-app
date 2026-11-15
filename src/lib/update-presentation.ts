import type {UpdateStatus} from "./app-model";
export function canConfirmUpdate(status:UpdateStatus):boolean {
  return status.protocol===2 && status.supported && !!status.offerId && ["available","downloading","ready_to_install","failed"].includes(status.phase);
}
export function updatePrompt(status:UpdateStatus,visible:boolean):string|null {
  return visible && status.promptPending && canConfirmUpdate(status) ? status.offerId! : null;
}
export function updateMessage(status:UpdateStatus):string {
  switch(status.phase){
    case "checking":return "Проверяем наличие новой версии…";
    case "downloading":return "Скачиваем обновление. VPN продолжает работать.";
    case "ready_to_install":return "Обновление скачано и проверено. Установка — после подтверждения.";
    case "installing":return "Устанавливаем обновление. Дождитесь завершения.";
    case "ready_to_restart":return "Перезапустите приложение, чтобы завершить обновление.";
    case "awaiting_installation":return "Завершите обновление в системном окне.";
    case "failed":return status.errorCode==="apk_install_cancelled" ? "Установка отменена. Можно повторить попытку." : "Обновление не завершено. Можно повторить попытку.";
    default:return status.notes || "Найдена новая версия приложения.";
  }
}
