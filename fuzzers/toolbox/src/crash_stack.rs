use alloc::borrow::Cow;
use std::fmt;

use backtrace::Backtrace;
use libafl::{
    common::{HasMetadata, HasNamedMetadata},
    corpus::Testcase,
    events::EventFirer,
    executors::ExitKind,
    feedbacks::{Feedback, HasObserverHandle, NewHashFeedback},
    inputs::UsesInput,
    observers::{BacktraceObserver, HarnessType, Observer, ObserverWithHashField, ObserversTuple},
    state::State,
};
use libafl_bolts::{impl_serdeany, Error, Named, 
    tuples::{Handle, MatchNameRef}};
use log::{info, warn};
use serde::{
    // Serializer,
    de::{self, Deserializer, MapAccess, SeqAccess, Visitor},
    Deserialize,
    Serialize,
};

/// BacktraceMetadata
/// The custom serialization below shows how to serialize in hex
#[derive(Debug)]
pub struct BacktraceMetadata {
    name: String,
    inner: Backtrace,
}

impl_serdeany!(BacktraceMetadata);

impl BacktraceMetadata {
    #[must_use]
    pub fn new(bt: Backtrace) -> Self {
        Self {
            name: std::any::type_name::<Self>().to_string(),
            inner: bt,
        }
    }
}
use serde::ser::{SerializeSeq, SerializeStruct, Serializer};
#[derive(Debug)]
pub struct PPFrame {
    ip: usize,
    symbol_address: usize,
    module_base_address: Option<usize>,
    symbols: String,
}
impl_serdeany!(PPFrame);
impl Serialize for PPFrame {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("PPFrame", 4)?;
        state.serialize_field("ip", &format!("{:#x}", self.ip))?;
        state.serialize_field("symbol_address", &format!("{:#x}", self.symbol_address))?;
        let base_address = self
            .module_base_address
            .map(|addr| format!("{:#x}", addr))
            .unwrap_or_else(|| "unknown".to_string());
        state.serialize_field("module_base_address", &base_address)?;
        state.serialize_field("symbols", &self.symbols)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for PPFrame {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_struct(
            "PPFrame",
            &["ip", "symbol_address", "module_base_address", "symbols"],
            PPFrameVisitor,
        )
    }
}

struct PPFrameVisitor;

impl<'de> Visitor<'de> for PPFrameVisitor {
    type Value = PPFrame;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("struct PPFrame")
    }

    fn visit_map<V>(self, mut map: V) -> Result<PPFrame, V::Error>
    where
        V: MapAccess<'de>,
    {
        let mut ip = None;
        let mut symbol_address = None;
        let mut module_base_address = None;
        let mut symbols = None;
        while let Some(key) = map.next_key()? {
            match key {
                "ip" => {
                    let ip_str: String = map.next_value()?;
                    ip = Some(
                        usize::from_str_radix(&ip_str.trim_start_matches("0x"), 16)
                            .map_err(de::Error::custom)?,
                    );
                }
                "symbol_address" => {
                    let symbol_address_str: String = map.next_value()?;
                    symbol_address = Some(
                        usize::from_str_radix(&symbol_address_str.trim_start_matches("0x"), 16)
                            .map_err(de::Error::custom)?,
                    );
                }
                "module_base_address" => {
                    let module_base_address_str: String = map.next_value()?;
                    if module_base_address_str != "unknown" {
                        module_base_address = Some(
                            usize::from_str_radix(
                                &module_base_address_str.trim_start_matches("0x"),
                                16,
                            )
                            .map_err(de::Error::custom)?,
                        );
                    }
                }
                "symbols" => {
                    symbols = map.next_value()?;
                }
                _ => (),
            }
        }

        let ip = ip.ok_or_else(|| de::Error::missing_field("ip"))?;
        let symbol_address =
            symbol_address.ok_or_else(|| de::Error::missing_field("symbol_address"))?;
        let symbols = symbols.ok_or_else(|| de::Error::missing_field("symbols"))?;

        Ok(PPFrame {
            ip,
            symbol_address,
            module_base_address,
            symbols,
        })
    }

    //For postcard, the struct is stored as a sequence, not map!
    fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
    where
        V: SeqAccess<'de>,
    {
        let ip_str = seq
            .next_element::<String>()?
            .ok_or_else(|| de::Error::invalid_length(0, &self))?;
        let ip = usize::from_str_radix(&ip_str.trim_start_matches("0x"), 16)
            .map_err(de::Error::custom)?;

        let symbol_address_str = seq
            .next_element::<String>()?
            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
        let symbol_address =
            usize::from_str_radix(&symbol_address_str.trim_start_matches("0x"), 16)
                .map_err(de::Error::custom)?;

        let module_base_address_str = seq.next_element::<String>()?;
        let module_base_address_str = match module_base_address_str {
            Some(s) if s != "unknown" => Some(
                usize::from_str_radix(&s.trim_start_matches("0x"), 16)
                    .map_err(de::Error::custom)?,
            ),
            _ => None,
        };
        let symbols = seq
            .next_element::<String>()?
            .ok_or_else(|| de::Error::invalid_length(1, &self))?;

        Ok(PPFrame {
            ip,
            symbol_address,
            module_base_address: module_base_address_str,
            symbols: symbols,
        })
    }
}

impl Serialize for BacktraceMetadata {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let frames = self.inner.frames();
        // let hex_frames: Vec<String> = frames
        //     .iter()
        //     .map(|frame| {
        //         let base_address = frame.module_base_address()
        //             .map(|addr| format!("{:?}", addr))
        //             .unwrap_or_else(|| "unknown".to_string());
        //         // format as a JSON string
        //         format!("{{\"base\": {}, \"ip\": {:?}}}", base_address, frame.ip())
        //     })
        //     .collect();
        // let hex_string = hex_frames.join(", ");
        // serializer.serialize_str(&hex_string)
        let mut seq = serializer.serialize_seq(Some(frames.len() + 1))?;
        seq.serialize_element(&self.name)?;
        for frame in frames {
            let pp_frame = PPFrame {
                ip: frame.ip() as usize,
                symbol_address: frame.symbol_address() as usize,
                module_base_address: frame.module_base_address().map(|addr| addr as usize),
                symbols: frame
                    .symbols()
                    .get(0)
                    .map(|symbol| format!("{:?}", symbol))
                    .unwrap_or_else(|| "No symbol".to_string()),
            };
            seq.serialize_element(&pp_frame)?;
        }
        seq.end()
    }
}

// // The implementation below is not correct, as it does not actually parses
// // The string and creates frames out of it.
// // Alas, I was not able to do it. The way BacktraceFrame is implemented,
// // it is not possible to create a frame outside of the crate
// // However, I don't think this function is needed.
// // BUT, whithout it, I get weird crashes.
struct BacktraceMetadataVisitor;

impl<'de> Visitor<'de> for BacktraceMetadataVisitor {
    type Value = BacktraceMetadata;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a sequence of BacktraceMetadata")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<BacktraceMetadata, A::Error>
    where
        A: SeqAccess<'de>,
    {
        // Read all elements from the sequence
        // while let Some(_) = seq.next_element::<HashMap<String, Self::Value>>()? {}
        // Read the name string and discard it
        let _ = seq.next_element::<String>().map_err(|err| err);
        while let Some(_) = seq.next_element::<PPFrame>().map_err(|err| err)? {}
        // Always return a current BacktraceMetadata.
        Ok(BacktraceMetadata::new(Backtrace::new_unresolved()))
    }
}

impl<'de> Deserialize<'de> for BacktraceMetadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(BacktraceMetadataVisitor)
        // Ignore the deserialized value and return an empty BacktraceMetadata
        // let _ = Deserialize::deserialize(deserializer)?;
        // Ok(BacktraceMetadata(Backtrace::new_unresolved()))
    }
}

/// My custom backtrace observer wrapping BacktraceObserver
/// Keeps the backtrace and returns it to the Feedback
/// I guess I need to create a special trait for this functionality
/// I did not find any more elegant way of implementing this

#[allow(clippy::unsafe_derive_deserialize)]
#[derive(Serialize, Deserialize, Debug)]
pub struct BacktraceObserverWithStack<'a> {
    inner: BacktraceObserver<'a>,
    harness_type: HarnessType,
    b: Option<Backtrace>,
    with_symbols: bool,
}

impl<'a> BacktraceObserverWithStack<'a> {
    /// Creates a new [`BacktraceObserverWithStack`] with the given name.
    #[must_use]
    pub fn new<S>(
        observer_name: S,
        backtrace_hash: &'a mut Option<u64>,
        harness_type: HarnessType,
        with_symbols: bool,
    ) -> Self 
    where
        S: Into<Cow<'static, str>>,
    {
        Self {
            inner: BacktraceObserver::new(
                observer_name.into(),
                libafl_bolts::ownedref::OwnedRefMut::Ref(backtrace_hash),
                harness_type.clone(),
            ),
            harness_type,
            b: None,
            with_symbols,
        }
    }

    //add a method that returns the backtrace
    pub fn get_backtrace(&self) -> Option<&Backtrace> {
        self.b.as_ref()
    }
}

impl<'a> ObserverWithHashField for BacktraceObserverWithStack<'a> {
    /// Gets the hash value of this observer.
    #[must_use]
    fn hash(&self) -> Option<u64> {
        self.inner.hash()
    }
}

impl<'a, S> Observer<S> for BacktraceObserverWithStack<'a>
where
    S: UsesInput,
{
    fn post_exec(
        &mut self,
        state: &mut S,
        input: &S::Input,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        self.inner.post_exec(state, input, exit_kind)?;

        // Rest of your code...
        if self.harness_type == HarnessType::InProcess {
            if *exit_kind == ExitKind::Crash {
                self.b = Some(match self.with_symbols {
                    false => Backtrace::new_unresolved(),
                    true => Backtrace::new(),
                });
            } else {
                self.b = None;
            }
        }

        Ok(())
    }

    fn post_exec_child(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        self.inner.post_exec_child(_state, _input, exit_kind)?;
        if self.harness_type == HarnessType::Child {
            if *exit_kind == ExitKind::Crash {
                self.b = Some(Backtrace::new_unresolved());
            } else {
                self.b = None;
            }
        }
        Ok(())
    }
}

impl<'a> Named for BacktraceObserverWithStack<'a> {
    fn name(&self) -> &Cow<'static, str> {
        self.inner.name()
    }
}

///
/// My custom feedback wrapping NewHashFeedback
/// I did not find any more elegant way of implementing this
#[derive(Serialize, Deserialize, Debug)]
pub struct NewHashFeedbackWithStack<'a, S>(NewHashFeedback<BacktraceObserverWithStack<'a>, S>);

impl<'a, S> Feedback<S> for NewHashFeedbackWithStack<'a, S>
where
    S: State + HasNamedMetadata + std::fmt::Debug,
{
    fn init_state(&mut self, state: &mut S) -> Result<(), Error> {
        self.0.init_state(state)
    }

    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _input: &<S as UsesInput>::Input,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        //Delegate to the self.inner
        self.0
            .is_interesting(state, _manager, _input, observers, _exit_kind)
    }

    /// Append to the testcase the generated metadata in case of a new corpus item
    #[inline]
    #[allow(unused_variables)]
    fn append_metadata<EM, OT>(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        observers: &OT,
        testcase: &mut Testcase<S::Input>,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<S>,
        EM: EventFirer<State = S>,
    {
        info!(
            "{}: append_metadata called!",
            std::process::id().to_string()
        );
        // let observer = observers
        //     .match_name::<BacktraceObserverWithStack>(&self.0.observer_name())
        //     .expect("A NewHashFeedbackWithStack needs a BacktraceObserverWithStack");
        let observer = observers
            .get(&self.0.observer_handle())
            .expect("A NewHashFeedbackWithStack needs a BacktraceObserverWithStack");

        
        match observer.get_backtrace() {
            // Performance problem here!
            Some(b) => testcase.add_metadata(BacktraceMetadata::new(b.clone())),
            None => warn! {"{}: append_metadata did not find backtrace!",
            std::process::id().to_string()},
        }

        Ok(())
    }
}

impl<'a, S> Named for NewHashFeedbackWithStack<'a, S> {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        self.0.name()
    }
}

impl<'a, S> HasObserverHandle for NewHashFeedbackWithStack<'a, S> {
    type Observer = BacktraceObserverWithStack<'a>;

    #[inline]
    fn observer_handle(&self) -> &Handle<BacktraceObserverWithStack<'a>> {
        self.0.observer_handle()
    }
}

impl<'a, S> NewHashFeedbackWithStack<'a, S>
{
    /// Returns a new [`NewHashFeedbackWithStack`].
    #[must_use]
    pub fn new(observer: &BacktraceObserverWithStack<'a>) -> Self {
        Self(NewHashFeedback::new(observer))
    }
}

#[cfg(test)]
#[test]
fn test_backtrace_metadata_serialization() {
    for backtrace in [Backtrace::new_unresolved(), Backtrace::new()].iter() {
        let backtrace_metadata = BacktraceMetadata::new(backtrace.clone());
        let serialized = serde_json::to_string(&backtrace_metadata).unwrap();
        println!("serialized = {}, len {}", serialized, serialized.len());
        let deserialized: BacktraceMetadata = serde_json::from_str(&serialized).unwrap();
        println!("deserialized = {:?}", deserialized);
        // assert_eq!(backtrace_metadata.inner.frames().len(), deserialized.inner.frames().len());
        assert!(deserialized.inner.frames().len() > 0);

        //test serializing to postcard
        let serialized = postcard::to_allocvec(&backtrace_metadata).unwrap();
        println!("serialized postcard len = {}", serialized.len());
        let deserialized: BacktraceMetadata = postcard::from_bytes(&serialized).unwrap();
        println!("deserialized = {:?}", deserialized);
        // assert_eq!(backtrace_metadata.inner.frames().len(), deserialized.inner.frames().len());
        assert!(deserialized.inner.frames().len() > 0);
    }
}
