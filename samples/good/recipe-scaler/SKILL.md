# Recipe Scaler

Reads a short recipe from a text file in its own folder and prints the
ingredients scaled to a different number of servings.

- Input: `recipe.txt` in this folder. The first line is the base serving
  count; every following line is `quantity unit ingredient`.
- Usage: `python scale_recipe.py 6` prints the recipe for 6 servings.
- It only reads the file next to it and prints the result. It does not write
  files or contact anything else.
