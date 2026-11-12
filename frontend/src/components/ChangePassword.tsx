import { useState } from "react";
import { Modal } from "./ui";
import { usePasswordForm } from "./usePasswordForm";

/** Окно «Сменить пароль» из карточки пользователя в меню. */
export function ChangePasswordModal({ onClose }: { onClose: () => void }) {
  const [done, setDone] = useState(false);
  const form = usePasswordForm(() => setDone(true));
  return (
    <Modal
      title="Смена пароля"
      onClose={onClose}
      footer={
        done ? (
          <button type="button" className="btn btn-primary" onClick={onClose}>
            Готово
          </button>
        ) : (
          <>
            <button type="button" className="btn" onClick={onClose}>
              Отмена
            </button>
            <button type="submit" form="change-password" className="btn btn-primary" disabled={form.busy || !form.ready}>
              {form.busy ? "Сохранение…" : "Сменить пароль"}
            </button>
          </>
        )
      }
    >
      {done ? (
        <div className="alert alert-ok">Пароль изменён. Сессии на других устройствах завершены, эта продолжается.</div>
      ) : (
        <form id="change-password" className="stack" style={{ gap: 14 }} onSubmit={form.submit}>
          <div className="alert alert-info">После смены пароля сессии на других устройствах будут завершены.</div>
          {form.fields}
        </form>
      )}
    </Modal>
  );
}
