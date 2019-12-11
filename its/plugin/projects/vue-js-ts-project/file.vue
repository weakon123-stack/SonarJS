<template>
  <p>Hello</p>
</template>

<script>
module.exports = {
  foo: function () {
    let a = [1, 2, 3];
    a.sort(); // Noncompliant
    return a;
  }
}
</script>

<style>
  p {
    text-align: center;
  }
</style>
