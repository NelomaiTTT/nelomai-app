import {describe,it,expect} from 'vitest';
import {updatePrompt,canConfirmUpdate,updateMessage} from './update-presentation';
import type {UpdateStatus} from './app-model';
const base:UpdateStatus={supported:true,automatic:true,protocol:2,phase:'ready_to_install',version:'0.4.1',notes:null,required:false,downloaded:0,total:null,errorCode:null,offerId:'one',promptPending:true,updateAvailable:true};
describe('owner update presentation',()=>{
 it('distinguishes Android cancellation from installer failure',()=>expect(updateMessage({...base,phase:'failed',errorCode:'apk_install_cancelled'})).toBe('Установка отменена. Можно повторить попытку.'));
 it('requires owner pending and visible UI, never local preference consent',()=>{
  expect(updatePrompt(base,true)).toBe('one');expect(updatePrompt(base,false)).toBeNull();
  expect(updatePrompt({...base,promptPending:false},true)).toBeNull();expect(updatePrompt({...base,protocol:1},true)).toBeNull();
 });
 it('permits early Yes but rejects terminal/legacy or absent offer',()=>{
  expect(canConfirmUpdate({...base,phase:'downloading'})).toBe(true);
  for(const phase of ['installing','ready_to_restart','awaiting_installation','checking','idle'] as const)expect(canConfirmUpdate({...base,phase})).toBe(false);
  expect(canConfirmUpdate({...base,offerId:null})).toBe(false);
 });
 it('does not describe prepared bytes as an installed version',()=>{
  expect(updateMessage(base)).toContain('подтверждения');
  expect(updateMessage({...base,phase:'installing'})).toContain('Устанавливаем');
 });
});
