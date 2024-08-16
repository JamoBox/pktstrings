use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

mod meta;

pub fn get_field(data: &[u8], offset: usize, bytelen: usize) -> Result<u128, &str> {
    assert!(bytelen <= 16, "Length must be less than 16 bytes");
    if (data.len() - offset) < bytelen {
        return Err("Data after offset is shorter than bytelen");
    }
    let mut addr: u128 = 0;
    for i in 0..(bytelen) {
        addr |= (data[offset + i] as u128) << (((bytelen - 1) * 8) - (i * 8))
    }
    Ok(addr)
}

macro_rules! m_get_field {
    ($data:expr, $offset:expr, $bits:expr, $uint_type:ty) => {{
        let uint_sz = std::mem::size_of::<$uint_type>();
        let bytes = ($bits / 8) as $uint_type;
        let bytes_round = if bytes > 1 { bytes } else { 1 };
        assert!(
            ($bits / 8) <= uint_sz,
            "Attempt to read more bits than possible in type"
        );
        if ($data.len() - $offset) < ($bits / 8) as usize {
            Err("Data after offset is shorter than uint_type")
        } else {
            let mut val: $uint_type = 0;
            for i in 0..(bytes_round) {
                let idx = ($offset as $uint_type + i) as usize;
                let data_byte = $data[idx] as $uint_type;
                val |= data_byte << ((bytes_round - 1) * 8) - (i * 8);
            }
            val &= ((1u128 << $bits as u128) - 1) as $uint_type;
            Ok(val)
        }
    }};
}

fn get_field_benches(c: &mut Criterion) {
    let mut field_group = c.benchmark_group("Byte Field Conversion Comparisons");
    for bytelen in 0..16 {
        field_group.throughput(Throughput::Bytes(bytelen as u64));

        field_group.bench_with_input(
            BenchmarkId::new("func_field_select", bytelen),
            &bytelen,
            |b, bytelen| {
                b.iter(|| get_field(meta::DATA, 0, *bytelen));
            },
        );

        match bytelen {
            0..=1 => {
                field_group.bench_with_input(
                    BenchmarkId::new("macro_field_select", bytelen),
                    &bytelen,
                    |b, bytelen| {
                        b.iter(|| m_get_field!(meta::DATA, 0, *bytelen, u8));
                    },
                );
            }
            2 => {
                field_group.bench_with_input(
                    BenchmarkId::new("macro_field_select", bytelen),
                    &bytelen,
                    |b, bytelen| {
                        b.iter(|| m_get_field!(meta::DATA, 0, *bytelen, u16));
                    },
                );
            }
            3..=4 => {
                field_group.bench_with_input(
                    BenchmarkId::new("macro_field_select", bytelen),
                    &bytelen,
                    |b, bytelen| {
                        b.iter(|| m_get_field!(meta::DATA, 0, *bytelen, u32));
                    },
                );
            }
            5..=8 => {
                field_group.bench_with_input(
                    BenchmarkId::new("macro_field_select", bytelen),
                    &bytelen,
                    |b, bytelen| {
                        b.iter(|| m_get_field!(meta::DATA, 0, *bytelen, u64));
                    },
                );
            }
            9..=16 => {
                field_group.bench_with_input(
                    BenchmarkId::new("macro_field_select", bytelen),
                    &bytelen,
                    |b, bytelen| {
                        b.iter(|| m_get_field!(meta::DATA, 0, *bytelen, u128));
                    },
                );
            }
            _ => {}
        }
    }
    field_group.finish();
}

criterion_group!(benches, get_field_benches);
criterion_main!(benches);
