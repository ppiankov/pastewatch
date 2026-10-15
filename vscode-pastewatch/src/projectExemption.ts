// WO-682@v2: only explicit CLI authorization may offer a project allow-file action.
export function canOfferProjectExemption(projectExemptible: unknown): boolean {
  return projectExemptible === true;
}
