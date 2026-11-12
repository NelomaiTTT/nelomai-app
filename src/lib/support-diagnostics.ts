export function supportErrorMessage(error: unknown): string {
  switch (error) {
    case "save_failed":
      return "Не удалось сохранить файл. Выберите другое место.";
    case "support_code_invalid":
      return "Код поддержки недействителен или истёк.";
    case "support_timeout":
      return "Панель не ответила вовремя. Отчёт можно сохранить или отправить повторно.";
    case "support_network_unavailable":
      return "Нет связи с панелью. Отчёт можно сохранить и отправить позже.";
    case "support_rate_limited":
      return "Панель временно ограничила отправку. Сохраните отчёт или повторите позже.";
    case "support_unavailable":
    case "support_rejected":
    case "support_receipt_invalid":
      return "Панель не подтвердила получение. Отчёт можно сохранить или отправить повторно.";
    case "report_expired":
      return "Соберите отчёт заново.";
    case "diagnostics_busy":
      return "Дождитесь окончания предыдущего действия.";
    default:
      return "Диагностика временно недоступна.";
  }
}
