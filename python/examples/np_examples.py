import numpy as np

a = np.array([[1, 2], [3, 4]])
b = np.array([[5, 6], [7, 8]])
c = np.array([1, 2, 3, 4])
d = np.array([5, 6, 7, 8])
# a = np.array([[1, 1, 1, 0], [2, 2, 2, 0], [3, 3, 3, 0], [4, 4, 4, 0]])
# b = np.array([[1, 0, 1, 0], [1, 1, 0, 0], [3, 0, 3, 0], [3, 0, 2, 0]])

print("a: \n", a)
print("b: \n", b)
print("c: \n", c)
print("d: \n", d)

# %%
print("Matrix multiplication:")
print(np.matmul(a, b))

# %%
print("\nDot product c.d:")
print(np.dot(c, d))

# %%
print("\nElement-wise multiplication a.b:")
print(np.multiply(a, b))

# %%
print("\nCreate matrix:")
m = np.matrix([[1, 2], [3, 4]])
print(m)

# %%
print("\nCreate array:")
arr = np.array([[1, 2], [3, 4]])
print(arr)

# %%
print("\nSum of array elements: sum(a)")
print(np.sum(a))

# %%
print("\nMean of array elements: mean(a)")
print(np.mean(a))

# %%
print("\nAddition: a+b")
print(np.add(a, b))

# %%
print("\nSubtraction: a - b")
print(np.subtract(a, b))

# %%
print("\nReduce by addition:")
print("Before addition: ", c)
print(np.add.reduce(c))

# %%
print("\nReduce by subtraction:")
print("Before subtraction: ", c)
print(np.subtract.reduce(c))

# %%
print("\nAccumulate by addition:")
print("Before accumulate by addition: ", c)
print(np.add.accumulate(c))

# %%
print("\nAccumulate by subtraction:")
print("Before accumulate by subtraction: ", c)
print(np.subtract.accumulate(c))
