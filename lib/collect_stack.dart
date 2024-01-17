// Copyright (c) 2024, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:ffi';

import 'package:ffi/ffi.dart';

/// From collect_stack.cc
@Native<Void Function()>(symbol: 'SetCurrentThreadAsTarget')
external void setCurrentThreadAsTarget();

/// From collect_stack.cc
@Native<Pointer<Utf8> Function(Pointer<Int64>, Size)>(
    symbol: 'CollectStackTraceOfTargetThread')
external Pointer<Utf8> _collectStackTraceOfTargetThread(
    Pointer<Int64> buf, int bufSize);

/// `void *dlopen(const char *filename, int flags);`
///
/// See `man dlopen`
@Native<Pointer<Void> Function(Pointer<Utf8> path, Int)>(symbol: 'dlopen')
external Pointer<Void> _dlopen(Pointer<Utf8> path, int flags);

/// `int dladdr(const void *addr, Dl_info *info);`
///
/// See `man dladdr`
@Native<Int Function(Pointer<Void> addr, Pointer<DlInfo>)>(symbol: 'dladdr')
external int _dladdr(Pointer<Void> addr, Pointer<DlInfo> info);

/// Dl_info from dlfcn.h.
///
/// See `man dladdr`.
final class DlInfo extends Struct {
  external Pointer<Utf8> fileName;
  external Pointer<Void> baseAddress;
  external Pointer<Utf8> symbolName;
  external Pointer<Void> symbolAddress;
}

class NativeFrame {
  final NativeModule? module;
  final int pc;
  NativeFrame({this.module, required this.pc});
}

class NativeModule {
  final int id;
  final String path;
  final int baseAddress;
  NativeModule(
      {required this.id, required this.path, required this.baseAddress});
}

class NativeStack {
  final List<NativeFrame> frames;
  final List<NativeModule> modules;
  NativeStack({required this.frames, required this.modules});
}

NativeStack captureStackOfTargetThread() {
  return using((arena) {
    // Invoke CollectStackTrace from helper library.
    const maxStackDepth = 1024;
    final outputBuffer = arena.allocate<Int64>(sizeOf<Int64>() * maxStackDepth);
    final error = _collectStackTraceOfTargetThread(outputBuffer, maxStackDepth);
    if (error != nullptr) {
      final errorString = error.toDartString();
      malloc.free(error);
      throw StateError(errorString); // Something went wrong.
    }

    final dlInfo = arena.allocate<DlInfo>(sizeOf<DlInfo>());

    // Process stack trace: which is a sequence of hexadecimal numbers
    // separated by commas. For each frame try to locate base address
    // of the module it belongs to using |dladdr|.
    final modules = <String, NativeModule>{};
    final frames = outputBuffer
        .asTypedList(maxStackDepth)
        .takeWhile((value) => value != 0)
        .map((addr) {
      final found = _dladdr(Pointer<Void>.fromAddress(addr), dlInfo);
      if (found == 0) {
        return NativeFrame(pc: addr);
      }

      final modulePath = dlInfo.ref.fileName.toDartString();
      final module = modules[modulePath] ??= NativeModule(
        id: modules.length,
        path: modulePath,
        baseAddress: dlInfo.ref.baseAddress.address,
      );

      return NativeFrame(module: module, pc: addr);
    }).toList(growable: false);

    return NativeStack(
        frames: frames, modules: modules.values.toList(growable: false));
  });
}
